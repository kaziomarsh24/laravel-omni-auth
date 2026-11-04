<?php

namespace KaziOmar\OmniAuth\Tests;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use KaziOmar\OmniAuth\Facades\Omni;
use Laravel\Sanctum\PersonalAccessToken;

class SecurityAuditTest extends TestCase
{
    public function test_access_token_cannot_be_used_as_refresh_token_even_with_wildcard_abilities(): void
    {
        $user = TestUser::create([
            'name' => 'Security Tester',
            'email' => 'security@example.com',
            'password' => bcrypt('password123'),
        ]);

        // Create an access token with wildcard abilities ['*']
        $accessTokenObj = $user->createToken('access_token', ['*']);
        $accessToken = $accessTokenObj->plainTextToken;

        // Attacker attempts to call refresh using their access token
        $request = Request::create('/api/refresh', 'POST');
        $request->headers->set('X-Refresh-Token', $accessToken);
        $request->headers->set('X-Client-Type', 'mobile');

        $response = Omni::refresh($request);

        // Security assertion: Access token MUST be rejected with 403 Forbidden!
        $this->assertEquals(403, $response->getStatusCode());

        $content = json_decode($response->getContent(), true);
        $this->assertFalse($content['ok']);
        $this->assertEquals('Invalid token capability for refresh.', $content['message']);

        // Access token in database must NOT be revoked/tampered with
        $this->assertNotNull(PersonalAccessToken::findToken($accessToken));
    }

    public function test_registration_via_standard_request_strictly_guards_against_privilege_escalation(): void
    {
        // Malicious client payload attempting privilege escalation
        $payload = [
            'name' => 'Injected Attacker',
            'email' => 'injected@example.com',
            'password' => 'SafePassword123!',
            'password_confirmation' => 'SafePassword123!',
            'is_admin' => 1,
            'role' => 'super-admin',
            'email_verified_at' => '2026-01-01 00:00:00',
            'phone' => '+1-800-SAFE',
        ];

        $request = Request::create('/api/register', 'POST', $payload);

        $response = Omni::register($request, autoLogin: false);
        $this->assertEquals(201, $response->getStatusCode());

        $user = TestUser::where('email', 'injected@example.com')->first();
        $this->assertNotNull($user);

        // Safe unvalidated extra attribute (phone) is preserved
        $this->assertEquals('+1-800-SAFE', $user->phone);

        // Critical Security Assertion: Injected dangerous keys MUST NOT be assigned!
        $this->assertFalse((bool) $user->is_admin);
        $this->assertNull($user->role);
    }

    public function test_cookie_authenticated_state_changing_request_requires_csrf_protection_header(): void
    {
        $user = TestUser::create([
            'name' => 'Web User',
            'email' => 'webuser@example.com',
            'password' => bcrypt('password123'),
        ]);

        $tokenObj = $user->createToken('access_token', ['access-api']);
        $token = $tokenObj->plainTextToken;

        Route::post('/api/test-state-change', function () {
            return response()->json(['ok' => true]);
        })->middleware('omni.auth');

        // 1. Request via Cookie WITHOUT custom anti-CSRF header and without matching origin MUST fail with 403
        $csrfFailResponse = $this->call(
            'POST',
            '/api/test-state-change',
            [],
            ['omni_access_token' => $token],
            [],
            [
                'HTTP_ACCEPT' => 'application/json',
                'HTTP_ORIGIN' => 'https://malicious-cross-origin.com',
            ]
        );

        $csrfFailResponse->assertStatus(403);
        $this->assertStringContainsString('CSRF verification failed', $csrfFailResponse->json('message'));

        // 2. Request via Cookie WITH standard custom header (X-Requested-With / X-Client-Type) MUST succeed
        $csrfPassResponse = $this->call(
            'POST',
            '/api/test-state-change',
            [],
            ['omni_access_token' => $token],
            [],
            [
                'HTTP_ACCEPT' => 'application/json',
                'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest',
            ]
        );

        $csrfPassResponse->assertStatus(200);
        $this->assertTrue($csrfPassResponse->json('ok'));
    }

    public function test_distributed_brute_force_protection_locks_out_across_different_ips(): void
    {
        config([
            'omni-auth.rate_limiting.max_attempts' => 5,
            'omni-auth.rate_limiting.global_max_attempts' => 6,
        ]);

        $user = TestUser::create([
            'name' => 'Target Admin',
            'email' => 'admin@targetcorp.com',
            'password' => bcrypt('correct_password'),
        ]);

        // IP 1 fails 3 times
        for ($i = 0; $i < 3; $i++) {
            $req = Request::create('/api/login', 'POST', [
                'email' => 'admin@targetcorp.com',
                'password' => 'wrong',
            ], [], [], ['REMOTE_ADDR' => '192.168.1.1']);
            $res = Omni::attempt(['email' => 'admin@targetcorp.com', 'password' => 'wrong'], $req);
            $this->assertEquals(401, $res->getStatusCode());
        }

        // IP 2 fails 3 times (Total across IPs is now 6 = global_max_attempts)
        for ($i = 0; $i < 3; $i++) {
            $req = Request::create('/api/login', 'POST', [
                'email' => 'admin@targetcorp.com',
                'password' => 'wrong',
            ], [], [], ['REMOTE_ADDR' => '10.0.0.2']);
            $res = Omni::attempt(['email' => 'admin@targetcorp.com', 'password' => 'wrong'], $req);
            $this->assertEquals(401, $res->getStatusCode());
        }

        // IP 3 (a new innocent or attacker IP) makes 1 attempt on this account
        $req = Request::create('/api/login', 'POST', [
            'email' => 'admin@targetcorp.com',
            'password' => 'wrong',
        ], [], [], ['REMOTE_ADDR' => '172.16.0.3']);
        $globalLockedResponse = Omni::attempt(['email' => 'admin@targetcorp.com', 'password' => 'wrong'], $req);

        // Must trigger 429 globally due to distributed botnet detection
        $this->assertEquals(429, $globalLockedResponse->getStatusCode());
        $responseData = json_decode($globalLockedResponse->getContent(), true);
        $this->assertStringContainsString('multiple failed login attempts across networks', $responseData['message']);
    }
}
