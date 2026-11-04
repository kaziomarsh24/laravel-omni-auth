<?php

namespace KaziOmar\OmniAuth\Tests;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Support\Facades\Hash;
use KaziOmar\OmniAuth\Facades\Omni;
use Laravel\Sanctum\PersonalAccessToken;

class RoutesAndResourcesTest extends TestCase
{
    public function test_built_in_routes_are_registered_and_working(): void
    {
        // 1. Test POST /api/auth/register
        $regResponse = $this->postJson('/api/auth/register', [
            'name' => 'Route User',
            'email' => 'route@example.com',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
        ], [
            'X-Client-Type' => 'mobile',
        ]);

        $regResponse->assertStatus(201)
            ->assertJsonPath('ok', true)
            ->assertJsonStructure([
                'ok',
                'message',
                'data' => [
                    'access_token',
                    'refresh_token',
                    'user' => ['id', 'name', 'email'],
                ],
            ]);

        $accessToken = $regResponse->json('data.access_token');
        $refreshToken = $regResponse->json('data.refresh_token');

        // 2. Test GET /api/auth/me
        $meResponse = $this->getJson('/api/auth/me', [
            'Authorization' => "Bearer {$accessToken}",
        ]);

        $meResponse->assertStatus(200)
            ->assertJsonPath('ok', true)
            ->assertJsonPath('data.user.email', 'route@example.com');

        // 3. Test POST /api/auth/refresh
        $refreshResponse = $this->postJson('/api/auth/refresh', [], [
            'X-Client-Type' => 'mobile',
            'X-Refresh-Token' => $refreshToken,
        ]);

        $refreshResponse->assertStatus(200)
            ->assertJsonPath('ok', true)
            ->assertJsonStructure([
                'ok',
                'message',
                'data' => [
                    'access_token',
                    'refresh_token',
                ],
            ]);

        $newAccessToken = $refreshResponse->json('data.access_token');

        // 4. Test POST /api/auth/logout
        $logoutResponse = $this->postJson('/api/auth/logout', [], [
            'Authorization' => "Bearer {$newAccessToken}",
            'X-Client-Type' => 'mobile',
        ]);

        $logoutResponse->assertStatus(200)
            ->assertJsonPath('ok', true)
            ->assertJsonPath('message', 'Logged out successfully.');
    }

    public function test_custom_user_resource_override(): void
    {
        config(['omni-auth.user_resource' => TestCustomUserResource::class]);

        $user = TestUser::create([
            'name' => 'Custom Resource User',
            'email' => 'custom@example.com',
            'password' => Hash::make('secret123'),
        ]);

        $formatted = Omni::formatUserResponse($user);

        $this->assertArrayHasKey('custom_key', $formatted);
        $this->assertEquals('custom_value', $formatted['custom_key']);
        $this->assertArrayHasKey('avatar_url', $formatted);
        $this->assertEquals('https://example.com/avatar.jpg', $formatted['avatar_url']);
    }

    public function test_replay_attack_detection_locks_out_compromised_user_sessions(): void
    {
        $user = TestUser::create([
            'name' => 'Replay Victim',
            'email' => 'victim@example.com',
            'password' => Hash::make('secret123'),
        ]);

        // 1. Initial Login: issue mobile tokens
        $loginReq = Request::create('/api/auth/login', 'POST', [], [], [], [
            'HTTP_X_CLIENT_TYPE' => 'mobile',
        ]);
        $loginRes = Omni::issueTokenResponse($user, $loginReq);
        $loginData = json_decode($loginRes->getContent(), true)['data'];

        $originalRefreshToken = $loginData['refresh_token'];
        $this->assertNotNull(PersonalAccessToken::findToken($originalRefreshToken));

        // 2. Legitimate Refresh: user rotates token
        $refreshReq = Request::create('/api/auth/refresh', 'POST', [], [], [], [
            'HTTP_X_CLIENT_TYPE' => 'mobile',
            'HTTP_X_REFRESH_TOKEN' => $originalRefreshToken,
        ]);
        $refreshRes = Omni::refresh($refreshReq);
        $this->assertEquals(200, $refreshRes->getStatusCode());

        $newAccessData = json_decode($refreshRes->getContent(), true)['data'];
        $legitimateAccessToken = $newAccessData['access_token'];

        // Verify old refresh token is deleted from DB
        $this->assertNull(PersonalAccessToken::findToken($originalRefreshToken));

        // Create an additional active session for this user (e.g. tablet session)
        $user->createToken('tablet_session');
        $this->assertGreaterThan(0, $user->tokens()->count());

        // 3. Replay Attack: Attacker tries to use the already-rotated $originalRefreshToken!
        $replayReq = Request::create('/api/auth/refresh', 'POST', [], [], [], [
            'HTTP_X_CLIENT_TYPE' => 'mobile',
            'HTTP_X_REFRESH_TOKEN' => $originalRefreshToken,
        ]);
        $replayRes = Omni::refresh($replayReq);

        // Security Assertion 1: Must be rejected with 401 and security alert message
        $this->assertEquals(401, $replayRes->getStatusCode());
        $replayContent = json_decode($replayRes->getContent(), true);
        $this->assertFalse($replayContent['ok']);
        $this->assertStringContainsString('Token reuse detected', $replayContent['message']);

        // Security Assertion 2: All active tokens for this user MUST BE DESTROYED (Security Lockout)!
        $this->assertEquals(0, $user->tokens()->count(), 'All sessions for compromised user must be terminated!');

        // Security Assertion 3: Legitimate access token is now invalid because session was revoked
        $this->assertNull(PersonalAccessToken::findToken($legitimateAccessToken));
    }
}

class TestCustomUserResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'email' => $this->email,
            'custom_key' => 'custom_value',
            'avatar_url' => 'https://example.com/avatar.jpg',
        ];
    }
}
