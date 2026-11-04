<?php

namespace KaziOmar\OmniAuth\Tests;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\URL;
use KaziOmar\OmniAuth\Events\MagicLinkRequested;
use KaziOmar\OmniAuth\Facades\Omni;
use KaziOmar\OmniAuth\Models\AuthTwoFactor;
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

    public function test_refresh_token_cannot_access_protected_endpoint(): void
    {
        $user = TestUser::create([
            'name' => 'Protected User',
            'email' => 'protected@example.com',
            'password' => bcrypt('password123'),
        ]);

        $refreshToken = $user->createToken('refresh_token', ['refresh-token'])->plainTextToken;

        // Attacker attempts to use refresh token on protected /api/auth/me
        $response = $this->withHeaders([
            'Authorization' => 'Bearer ' . $refreshToken,
            'Accept' => 'application/json',
        ])->getJson('/api/auth/me');

        $this->assertContains($response->getStatusCode(), [401, 403]);
    }

    public function test_fake_apple_token_with_alg_none_is_strictly_rejected(): void
    {
        config()->set('omni-auth.social.providers.apple', [
            'client_id' => 'com.example.service',
            'team_id' => 'TEAM123456',
            'key_id' => 'KEY123456',
        ]);

        // Construct fake JWT with alg: none
        $header = rtrim(strtr(base64_encode(json_encode(['alg' => 'none', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode(json_encode([
            'iss' => 'https://appleid.apple.com',
            'aud' => 'com.example.service',
            'exp' => time() + 3600,
            'sub' => 'victim-apple-sub',
            'email' => 'victim@example.com',
            'email_verified' => 'true',
        ])), '+/', '-_'), '=');
        $fakeJwt = "{$header}.{$payload}.";

        $response = $this->postJson('/api/auth/social/exchange', [
            'provider' => 'apple',
            'id_token' => $fakeJwt,
        ]);

        $response->assertStatus(400);
        $this->assertStringContainsString('RS256 algorithm', $response->json('message'));
    }

    public function test_social_login_with_unverified_email_cannot_link_to_existing_account(): void
    {
        $user = TestUser::create([
            'name' => 'Target Account',
            'email' => 'victim@target.com',
            'password' => Hash::make('StrongPass123!'),
        ]);

        config()->set('omni-auth.social.providers.google', [
            'client_id' => 'test-google-id.apps.googleusercontent.com',
            'client_secret' => 'secret',
            'mobile_client_ids' => ['test-google-id.apps.googleusercontent.com'],
        ]);

        Http::fake([
            'https://oauth2.googleapis.com/tokeninfo*' => Http::response([
                'aud' => 'test-google-id.apps.googleusercontent.com',
                'sub' => 'attacker-google-sub',
                'email' => 'victim@target.com',
                'email_verified' => 'false', // Unverified!
                'name' => 'Attacker',
            ], 200),
        ]);

        $response = $this->postJson('/api/auth/social/exchange', [
            'provider' => 'google',
            'id_token' => 'mock-google-token',
        ]);

        $response->assertStatus(400);
        $this->assertStringContainsString('Cannot link unverified social email', $response->json('message'));
    }

    public function test_social_login_and_magic_link_enforce_2fa_challenge_when_enabled(): void
    {
        $user = TestUser::create([
            'name' => 'TwoFA Social User',
            'email' => 'twofa-social@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        // Enable 2FA on account
        AuthTwoFactor::create([
            'user_id' => $user->id,
            'secret' => Omni::twoFactor()->generateSecret(),
            'confirmed_at' => now(),
        ]);

        config()->set('omni-auth.social.providers.google', [
            'client_id' => 'test-client-id.apps.googleusercontent.com',
            'client_secret' => 'secret',
            'mobile_client_ids' => ['test-client-id.apps.googleusercontent.com'],
        ]);

        Http::fake([
            'https://oauth2.googleapis.com/tokeninfo*' => Http::response([
                'aud' => 'test-client-id.apps.googleusercontent.com',
                'sub' => 'google-sub-2fa-123',
                'email' => 'twofa-social@example.com',
                'email_verified' => 'true',
                'name' => 'TwoFA Social User',
            ], 200),
        ]);

        // 1. Social Exchange must require 2FA challenge
        $response = $this->postJson('/api/auth/social/exchange', [
            'provider' => 'google',
            'id_token' => 'mock-google-token',
        ]);

        $response->assertStatus(200);
        $this->assertTrue($response->json('data.requires_2fa'));
        $this->assertNotEmpty($response->json('data.two_factor_token'));
        $this->assertNull($response->json('access_token'));

        // 2. Magic Link must also require 2FA challenge
        Event::fake([MagicLinkRequested::class]);
        $magicReq = $this->postJson('/api/auth/magic-link', [
            'email' => 'twofa-social@example.com',
        ]);
        $magicReq->assertStatus(200);

        $magicCode = null;
        Event::assertDispatched(MagicLinkRequested::class, function ($event) use (&$magicCode) {
            $magicCode = $event->code;
            return true;
        });

        $callbackRes = $this->postJson('/api/auth/magic-link/verify', [
            'email' => 'twofa-social@example.com',
            'code' => $magicCode,
        ]);
        $callbackRes->assertStatus(200);
        $this->assertTrue($callbackRes->json('data.requires_2fa'));
        $this->assertNotEmpty($callbackRes->json('data.two_factor_token'));
        $this->assertNull($callbackRes->json('access_token'));
    }

    public function test_disabling_2fa_without_reauthentication_fails(): void
    {
        $user = TestUser::create([
            'name' => '2FA Secure User',
            'email' => 'secure-2fa@example.com',
            'password' => Hash::make('CorrectPassword123!'),
        ]);

        $secret = Omni::twoFactor()->generateSecret();
        AuthTwoFactor::create([
            'user_id' => $user->id,
            'secret' => $secret,
            'confirmed_at' => now(),
        ]);

        $this->actingAs($user, 'sanctum');

        // Missing password and code must fail with 422
        $response = $this->postJson('/api/auth/2fa/disable', []);
        $response->assertStatus(422);

        // Wrong password must fail
        $responseWrong = $this->postJson('/api/auth/2fa/disable', [
            'password' => 'wrong-password',
        ]);
        $responseWrong->assertStatus(422);

        // Still confirmed in database
        $this->assertNotNull(AuthTwoFactor::where('user_id', $user->id)->first()->confirmed_at);
    }

    public function test_email_verification_strictly_requires_valid_url_signature(): void
    {
        $user = TestUser::create([
            'name' => 'Unverified User',
            'email' => 'unverified@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        $hash = sha1('unverified@example.com');
        $tamperedUrl = "/api/auth/email/verify/{$user->id}/{$hash}?expires=" . (time() + 3600) . "&signature=invalid-tampered-signature";

        $response = $this->getJson($tamperedUrl);
        $response->assertStatus(422);
        $this->assertStringContainsString('Invalid, expired, or tampered verification link or code.', $response->json('message'));
        $this->assertNull($user->fresh()->email_verified_at);
    }

    public function test_magic_link_untrusted_redirect_host_is_strictly_blocked(): void
    {
        $response = $this->postJson('/api/auth/magic-link', [
            'email' => 'victim@example.com',
            'redirect_url' => 'https://evil-attacker.com/steal-token',
        ]);

        $response->assertStatus(422);
        $this->assertStringContainsString('Untrusted redirect URL domain', $response->json('message'));
    }

    public function test_totp_replay_attack_within_same_window_is_prevented(): void
    {
        $user = TestUser::create([
            'name' => 'TOTP Replay Victim',
            'email' => 'replay@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        $secret = Omni::twoFactor()->generateSecret();
        AuthTwoFactor::create([
            'user_id' => $user->id,
            'secret' => $secret,
            'confirmed_at' => now(),
        ]);

        $validCode = Omni::twoFactor()->calculateCode($secret);
        $twoFactorToken = Omni::twoFactor()->createChallengeToken($user);

        // First challenge attempt with validCode -> must succeed
        $response1 = $this->postJson('/api/auth/2fa/challenge', [
            'two_factor_token' => $twoFactorToken,
            'code' => $validCode,
        ]);
        $response1->assertStatus(200);

        // Attacker intercepts and replays validCode within the 30-second window
        $twoFactorToken2 = Omni::twoFactor()->createChallengeToken($user);
        $response2 = $this->postJson('/api/auth/2fa/challenge', [
            'two_factor_token' => $twoFactorToken2,
            'code' => $validCode,
        ]);
        $response2->assertStatus(422);
        $this->assertStringContainsString('Invalid or expired two-factor code.', $response2->json('message'));
    }
}
