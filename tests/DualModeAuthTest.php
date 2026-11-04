<?php

namespace KaziOmar\OmniAuth\Tests;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use KaziOmar\OmniAuth\Facades\Omni;
use Laravel\Sanctum\PersonalAccessToken;

class DualModeAuthTest extends TestCase
{
    protected TestUser $user;

    protected function setUp(): void
    {
        parent::setUp();

        $this->user = TestUser::create([
            'name' => 'Kazi Omar',
            'email' => 'omar@example.com',
            'password' => Hash::make('secret123'),
        ]);

        // Register a protected test route
        Route::get('/api/test-protected', function () {
            return response()->json([
                'ok' => true,
                'user_id' => auth('sanctum')->id(),
            ]);
        })->middleware('omni.auth');
    }

    public function test_attempt_fails_with_invalid_credentials(): void
    {
        $response = Omni::attempt([
            'email' => 'omar@example.com',
            'password' => 'wrong_password',
        ]);

        $this->assertEquals(401, $response->getStatusCode());
        $data = json_decode($response->getContent(), true);
        $this->assertFalse($data['ok']);
        $this->assertEquals('Invalid credentials.', $data['message']);
    }

    public function test_attempt_delivers_httponly_cookies_for_web_clients(): void
    {
        // 1. Web request (no mobile header)
        $request = \Illuminate\Http\Request::create('/api/login', 'POST', [
            'email' => 'omar@example.com',
            'password' => 'secret123',
        ]);

        $response = Omni::attempt([
            'email' => 'omar@example.com',
            'password' => 'secret123',
        ], $request);

        $this->assertEquals(200, $response->getStatusCode());
        $data = json_decode($response->getContent(), true);

        // Security assertion: Access tokens MUST NOT be exposed in the response body for web clients!
        $this->assertArrayNotHasKey('access_token', $data['data']);
        $this->assertEquals('omar@example.com', $data['data']['user']['email']);

        // Assert cookies are attached
        $cookies = $response->headers->getCookies();
        $this->assertNotEmpty($cookies);

        $cookieNames = array_map(fn($c) => $c->getName(), $cookies);
        $this->assertContains('omni_access_token', $cookieNames);
        $this->assertContains('omni_refresh_token', $cookieNames);

        // Assert cookie security flags: HttpOnly=true, SameSite=lax
        foreach ($cookies as $cookie) {
            if ($cookie->getName() === 'omni_access_token') {
                $this->assertTrue($cookie->isHttpOnly(), 'Access token cookie must be HttpOnly to prevent XSS theft.');
                $this->assertEquals('lax', $cookie->getSameSite());
                $this->assertNotEmpty($cookie->getValue());
            }
        }
    }

    public function test_attempt_delivers_bearer_tokens_in_json_for_mobile_clients(): void
    {
        // 1. Mobile request with explicit X-Client-Type: mobile header
        $request = \Illuminate\Http\Request::create('/api/login', 'POST', [
            'email' => 'omar@example.com',
            'password' => 'secret123',
        ]);
        $request->headers->set('X-Client-Type', 'mobile');

        $response = Omni::attempt([
            'email' => 'omar@example.com',
            'password' => 'secret123',
        ], $request);

        $this->assertEquals(200, $response->getStatusCode());
        $data = json_decode($response->getContent(), true);

        // Mobile assertions: Bearer and Refresh tokens delivered in body
        $this->assertTrue($data['ok']);
        $this->assertArrayHasKey('access_token', $data['data']);
        $this->assertArrayHasKey('refresh_token', $data['data']);
        $this->assertEquals('Bearer', $data['data']['token_type']);
        $this->assertNotEmpty($data['data']['access_token']);

        // Security assertion: No web cookies should be set for mobile clients
        $cookies = $response->headers->getCookies();
        $this->assertEmpty($cookies, 'Mobile responses should not set browser cookies.');
    }

    public function test_middleware_authenticates_mobile_via_bearer_header(): void
    {
        $token = $this->user->createToken('test_token')->plainTextToken;

        $response = $this->withHeader('Authorization', 'Bearer ' . $token)
            ->getJson('/api/test-protected');

        $response->assertStatus(200)
            ->assertJson([
                'ok' => true,
                'user_id' => $this->user->id,
            ]);
    }

    public function test_middleware_authenticates_web_via_httponly_cookie(): void
    {
        $token = $this->user->createToken('test_token')->plainTextToken;

        // Make request without Authorization header, but WITH omni_access_token cookie
        $response = $this->call('GET', '/api/test-protected', [], ['omni_access_token' => $token], [], ['HTTP_ACCEPT' => 'application/json']);

        $response->assertStatus(200)
            ->assertJson([
                'ok' => true,
                'user_id' => $this->user->id,
            ]);
    }

    public function test_middleware_rejects_unauthenticated_requests(): void
    {
        $response = $this->getJson('/api/test-protected');

        $response->assertStatus(401)
            ->assertJson([
                'ok' => false,
                'message' => 'Unauthenticated.',
            ]);
    }

    public function test_refresh_rotates_tokens_for_mobile_and_revokes_old_refresh_token(): void
    {
        // 1. Issue initial mobile login
        $mobileReq = \Illuminate\Http\Request::create('/api/login', 'POST');
        $mobileReq->headers->set('X-Client-Type', 'mobile');

        $loginRes = Omni::issueTokenResponse($this->user, $mobileReq);
        $loginData = json_decode($loginRes->getContent(), true)['data'];
        $oldRefreshToken = $loginData['refresh_token'];

        $this->assertNotEmpty($oldRefreshToken);

        // Verify token exists in database
        $this->assertNotNull(PersonalAccessToken::findToken($oldRefreshToken));

        // 2. Perform refresh using mobile header
        $refreshReq = \Illuminate\Http\Request::create('/api/refresh', 'POST');
        $refreshReq->headers->set('X-Client-Type', 'mobile');
        $refreshReq->headers->set('X-Refresh-Token', $oldRefreshToken);

        $refreshRes = Omni::refresh($refreshReq);
        $this->assertEquals(200, $refreshRes->getStatusCode());

        $refreshData = json_decode($refreshRes->getContent(), true)['data'];
        $newRefreshToken = $refreshData['refresh_token'];
        $newAccessToken = $refreshData['access_token'];

        $this->assertNotEquals($oldRefreshToken, $newRefreshToken, 'Refresh token must be rotated.');
        $this->assertNotEmpty($newAccessToken);

        // Security assertion: Old refresh token MUST be permanently revoked to prevent replay attacks!
        $this->assertNull(PersonalAccessToken::findToken($oldRefreshToken), 'Old refresh token must be revoked.');

        // 3. Attempting to replay old refresh token MUST fail with 401
        $replayReq = \Illuminate\Http\Request::create('/api/refresh', 'POST');
        $replayReq->headers->set('X-Client-Type', 'mobile');
        $replayReq->headers->set('X-Refresh-Token', $oldRefreshToken);

        $replayRes = Omni::refresh($replayReq);
        $this->assertEquals(401, $replayRes->getStatusCode());
    }

    public function test_rate_limiting_locks_out_after_max_failed_attempts(): void
    {
        $credentials = [
            'email' => 'omar@example.com',
            'password' => 'wrong_pass',
        ];

        // Fail 5 times (configured max_attempts)
        for ($i = 0; $i < 5; $i++) {
            $res = Omni::attempt($credentials);
            $this->assertEquals(401, $res->getStatusCode());
        }

        // 6th attempt MUST trigger 429 Too Many Requests
        $lockedRes = Omni::attempt($credentials);
        $this->assertEquals(429, $lockedRes->getStatusCode());

        $data = json_decode($lockedRes->getContent(), true);
        $this->assertStringContainsString('Too many login attempts', $data['message']);
        $this->assertArrayHasKey('retry_after', $data);
    }

    public function test_login_and_logout_fire_standard_laravel_auth_events(): void
    {
        Event::fake([Login::class, Failed::class, Logout::class]);

        // 1. Failed login event
        Omni::attempt(['email' => 'omar@example.com', 'password' => 'wrong']);
        Event::assertDispatched(Failed::class);

        // 2. Successful login event
        Omni::attempt(['email' => 'omar@example.com', 'password' => 'secret123']);
        Event::assertDispatched(Login::class);

        // 3. Logout event
        $this->actingAs($this->user, 'sanctum');
        Omni::logout();
        Event::assertDispatched(Logout::class);
    }

    public function test_logout_revokes_token_and_clears_cookies_for_web(): void
    {
        $tokenObj = $this->user->createToken('test_token');
        $token = $tokenObj->plainTextToken;

        // Mock current authenticated user
        $this->actingAs($this->user, 'sanctum');

        $response = Omni::logout();
        $this->assertEquals(200, $response->getStatusCode());

        // Assert expired cookie was attached
        $cookies = $response->headers->getCookies();
        $this->assertNotEmpty($cookies);

        $expiredCookies = array_filter($cookies, fn($c) => $c->getExpiresTime() < time());
        $this->assertNotEmpty($expiredCookies, 'Logout must issue expired cookies to clear browser state.');
    }
}
