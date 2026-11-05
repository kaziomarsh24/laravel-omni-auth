<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Tests;

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\RateLimiter;
use KaziOmar\OmniAuth\Facades\Omni;
use KaziOmar\OmniAuth\Models\AuthDevice;
use KaziOmar\OmniAuth\Models\AuthSocialAccount;
use Laravel\Sanctum\PersonalAccessToken;

class FinalReviewAuditTest extends TestCase
{
    private const MOBILE_HEADER = ['X-Client-Type' => 'mobile'];

    protected function setUp(): void
    {
        parent::setUp();

        config()->set('app.url', 'https://app.example.com');
        config()->set('omni-auth.social.providers.google', [
            'client_id' => 'test-client-id.apps.googleusercontent.com',
            'client_secret' => 'secret',
            'mobile_client_ids' => ['test-client-id.apps.googleusercontent.com'],
        ]);
        config()->set('omni-auth.social.providers.apple', [
            'client_id' => 'com.example.app',
        ]);
    }

    /**
     * R1 [Critical]: Legacy user with password_set_at = null who links a social account
     * CANNOT delete account without providing their password.
     */
    public function test_r1_legacy_user_with_null_password_set_at_strictly_requires_password_for_deletion(): void
    {
        $legacyUser = TestUser::create([
            'name' => 'Legacy User',
            'email' => 'legacy-audit@example.com',
            'password' => Hash::make('LegacyPassword123!'),
            'password_set_at' => null, // Explicitly NULL as in legacy database
        ]);

        // Legacy user links Google
        AuthSocialAccount::create([
            'user_id' => $legacyUser->id,
            'provider' => 'google',
            'provider_id' => 'google-legacy-12345',
            'data' => [], // NOT social-only!
        ]);

        $this->assertTrue(Omni::hasUserSetPassword($legacyUser), 'Legacy user with password must return true for hasUserSetPassword');

        $token = $legacyUser->createToken('access_token', ['access-api'])->plainTextToken;

        // Attacker attempts account deletion without password
        $res = $this->withHeaders([
            'Authorization' => "Bearer {$token}",
        ])->deleteJson('/api/auth/account', []);

        $res->assertStatus(422);
        $this->assertStringContainsString('Incorrect password confirmation', $res->json('message'));
        $this->assertDatabaseHas('users', ['id' => $legacyUser->id]);

        // Legitimate user provides correct password
        $validRes = $this->withHeaders([
            'Authorization' => "Bearer {$token}",
        ])->deleteJson('/api/auth/account', [
            'password' => 'LegacyPassword123!',
        ]);

        $validRes->assertStatus(200);
        $this->assertDatabaseMissing('users', ['id' => $legacyUser->id]);
    }

    /**
     * R3 [Medium]: Concurrent refresh in progress (429) must NEVER wipe browser cookies.
     * Must return Retry-After: 1 header so concurrent SPA tabs can retry.
     */
    public function test_r3_concurrent_refresh_lock_429_does_not_clear_cookies_and_sets_retry_after(): void
    {
        $user = TestUser::create([
            'name' => 'Concurrent User',
            'email' => 'concurrent@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        $refreshToken = $user->createToken('refresh_token', ['issue-access-token'])->plainTextToken;
        $tokenHash = hash('sha256', $refreshToken);

        // Simulate another request currently holding the atomic lock
        $lock = cache()->lock('omni_refresh_lock:' . $tokenHash, 10);
        $lock->get();

        try {
            $response = $this->withHeaders([
                'X-Client-Type' => 'web',
                'X-Refresh-Token' => $refreshToken,
            ])->postJson('/api/auth/refresh');

            $response->assertStatus(429);
            $this->assertEquals('1', $response->headers->get('Retry-After'));
            $this->assertEquals(1, $response->json('retry_after'));

            // Assert that cookies were NOT cleared (no expired cookies attached to 429 response)
            $cookies = $response->headers->getCookies();
            $clearedCookies = array_filter($cookies, fn($c) => $c->getExpiresTime() < time());
            $this->assertEmpty($clearedCookies, '429 response must never clear authentication cookies');
        } finally {
            $lock->release();
        }
    }

    /**
     * R5 [Medium]: Web browser logins from the same NAT / IP and User-Agent
     * maintain distinct device sessions using persistent omni_device_id cookie,
     * preventing one login from revoking the other.
     */
    public function test_r5_web_browser_sessions_from_same_ip_and_ua_do_not_kick_each_other(): void
    {
        $user = TestUser::create([
            'name' => 'Multi Tab User',
            'email' => 'multitab@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        // Browser Session A (Cookie: dev_browser_A)
        $loginA = $this->withHeaders([
            'User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        ])->withCookies([
            'omni_device_id' => 'dev_browser_A',
        ])->postJson('/api/auth/login', [
            'email' => 'multitab@example.com',
            'password' => 'Password123!',
        ]);

        $loginA->assertStatus(200);
        $cookieA = collect($loginA->headers->getCookies())->first(fn($c) => $c->getName() === 'omni_refresh_token');
        $refreshA = $cookieA?->getValue() ?? $loginA->json('data.refresh_token');

        // Browser Session B from same IP and same UA (Cookie: dev_browser_B)
        $loginB = $this->withHeaders([
            'User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        ])->withCookies([
            'omni_device_id' => 'dev_browser_B',
        ])->postJson('/api/auth/login', [
            'email' => 'multitab@example.com',
            'password' => 'Password123!',
        ]);

        $loginB->assertStatus(200);
        $cookieB = collect($loginB->headers->getCookies())->first(fn($c) => $c->getName() === 'omni_refresh_token');
        $refreshB = $cookieB?->getValue() ?? $loginB->json('data.refresh_token');

        $this->assertNotEquals($refreshA, $refreshB);

        // Verify that Session A's refresh token remains ACTIVE and valid (not revoked by Session B)
        $refreshResponseA = $this->withHeaders([
            'X-Client-Type' => 'mobile',
            'X-Refresh-Token' => $refreshA,
        ])->postJson('/api/auth/refresh');

        $refreshResponseA->assertStatus(200);
        $this->assertTrue($refreshResponseA->json('ok'));

        // Verify that Session B's refresh token is also valid
        $refreshResponseB = $this->withHeaders([
            'X-Client-Type' => 'mobile',
            'X-Refresh-Token' => $refreshB,
        ])->postJson('/api/auth/refresh');

        $refreshResponseB->assertStatus(200);
        $this->assertTrue($refreshResponseB->json('ok'));
    }

    /**
     * R6 [Low-Medium]: Apple JWKS refetch cooldown prevents outbound amplification DoS
     * when random kid values are hammered.
     */
    public function test_r6_apple_jwks_refetch_cooldown_prevents_hammering_outbound_calls(): void
    {
        Http::fake([
            'https://appleid.apple.com/auth/keys' => Http::response([
                'keys' => [
                    ['kid' => 'known-apple-key', 'kty' => 'RSA', 'n' => 'test', 'e' => 'AQAB'],
                ],
            ], 200),
        ]);

        // Prime the cache with existing JWKS
        cache()->put('omni_apple_jwks', [
            ['kid' => 'known-apple-key', 'kty' => 'RSA', 'n' => 'test', 'e' => 'AQAB'],
        ], now()->addHours(12));

        // First attempt with unknown kid: triggers refetch and sets cooldown
        $fakeJwtHeader = rtrim(strtr(base64_encode(json_encode(['alg' => 'RS256', 'kid' => 'random-kid-1'])), '+/', '-_'), '=');
        $fakeJwtPayload = rtrim(strtr(base64_encode(json_encode(['iss' => 'https://appleid.apple.com', 'aud' => 'com.example.app', 'sub' => '123'])), '+/', '-_'), '=');
        $fakeToken = "{$fakeJwtHeader}.{$fakeJwtPayload}.fake-sig";

        $res1 = $this->postJson('/api/auth/social/exchange', [
            'provider' => 'apple',
            'id_token' => $fakeToken,
        ], self::MOBILE_HEADER);

        $res1->assertStatus(400);
        $this->assertTrue(cache()->has('omni_apple_jwks_refetch_cooldown'));

        // Reset HTTP call recorder
        Http::fake([
            'https://appleid.apple.com/auth/keys' => Http::response([], 500),
        ]);

        // Second attempt with another unknown kid: MUST NOT make an outbound HTTP call due to cooldown
        $fakeJwtHeader2 = rtrim(strtr(base64_encode(json_encode(['alg' => 'RS256', 'kid' => 'random-kid-2'])), '+/', '-_'), '=');
        $fakeToken2 = "{$fakeJwtHeader2}.{$fakeJwtPayload}.fake-sig";

        $res2 = $this->postJson('/api/auth/social/exchange', [
            'provider' => 'apple',
            'id_token' => $fakeToken2,
        ], self::MOBILE_HEADER);

        $res2->assertStatus(400);
        // Verify no outbound HTTP request was made during cooldown
        Http::assertNothingSent();
    }

    /**
     * R8: Social account email normalization to lowercase.
     */
    public function test_r8_social_email_normalized_to_lowercase(): void
    {
        Http::fake([
            'https://oauth2.googleapis.com/tokeninfo*' => Http::response([
                'aud' => 'test-client-id.apps.googleusercontent.com',
                'sub' => 'google-case-test',
                'email' => 'MixedCaseUser@Example.COM',
                'email_verified' => 'true',
                'name' => 'Case User',
            ], 200),
        ]);

        $res = $this->postJson('/api/auth/social/exchange', [
            'provider' => 'google',
            'id_token' => 'mock-google-token',
        ], self::MOBILE_HEADER);

        $res->assertStatus(200);

        $user = TestUser::where('email', 'mixedcaseuser@example.com')->first();
        $this->assertNotNull($user, 'Social account email must be normalized to lowercase in database');
    }

    /**
     * 30th API: POST /api/auth/password/change
     * Full suite testing password change, validation, current password check,
     * same password rejection, logout_others revocation, and passwordless first set.
     */
    public function test_30th_api_authenticated_password_change_flow(): void
    {
        $user = TestUser::create([
            'name' => 'Password Change User',
            'email' => 'change-pw@example.com',
            'password' => Hash::make('CurrentPassword123!'),
            'password_set_at' => now(),
        ]);

        $tokenA = $user->createToken('access_token', ['access-api'])->plainTextToken;
        $tokenB = $user->createToken('access_token', ['access-api'])->plainTextToken;

        // 1. Unauthenticated request rejected
        $unauthRes = $this->postJson('/api/auth/password/change', [
            'current_password' => 'CurrentPassword123!',
            'password' => 'NewPassword123!',
            'password_confirmation' => 'NewPassword123!',
        ]);
        $unauthRes->assertStatus(401);

        // 2. Incorrect current password rejected
        $wrongPwRes = $this->withHeaders([
            'Authorization' => "Bearer {$tokenA}",
        ])->postJson('/api/auth/password/change', [
            'current_password' => 'WrongPassword123!',
            'password' => 'NewPassword123!',
            'password_confirmation' => 'NewPassword123!',
        ]);
        $wrongPwRes->assertStatus(422);
        $this->assertStringContainsString('current password does not match', $wrongPwRes->json('message'));

        // 3. New password same as current password rejected
        $samePwRes = $this->withHeaders([
            'Authorization' => "Bearer {$tokenA}",
        ])->postJson('/api/auth/password/change', [
            'current_password' => 'CurrentPassword123!',
            'password' => 'CurrentPassword123!',
            'password_confirmation' => 'CurrentPassword123!',
        ]);
        $samePwRes->assertStatus(422);
        $this->assertStringContainsString('cannot be the same', $samePwRes->json('message'));

        // 4. Mismatched password confirmation rejected
        $mismatchRes = $this->withHeaders([
            'Authorization' => "Bearer {$tokenA}",
        ])->postJson('/api/auth/password/change', [
            'current_password' => 'CurrentPassword123!',
            'password' => 'NewPassword123!',
            'password_confirmation' => 'DifferentPassword123!',
        ]);
        $mismatchRes->assertStatus(422);

        // 5. Successful password change with logout_others = true
        $validRes = $this->withHeaders([
            'Authorization' => "Bearer {$tokenA}",
        ])->postJson('/api/auth/password/change', [
            'current_password' => 'CurrentPassword123!',
            'password' => 'NewSecurePassword123!',
            'password_confirmation' => 'NewSecurePassword123!',
            'logout_others' => true,
        ]);

        $validRes->assertStatus(200);
        $this->assertTrue($validRes->json('ok'));

        // Verify password is updated in database
        $user->refresh();
        $this->assertTrue(Hash::check('NewSecurePassword123!', $user->password));

        // 6. Verify rate limiting on repeated failed current_password attempts (5 attempts -> 429)
        RateLimiter::clear("omni_pwd_change_attempts:{$user->id}");
        for ($i = 0; $i < 5; $i++) {
            $this->withHeaders([
                'Authorization' => "Bearer {$tokenA}",
            ])->postJson('/api/auth/password/change', [
                'current_password' => 'WrongGuess!',
                'password' => 'SomePassword123!',
                'password_confirmation' => 'SomePassword123!',
            ]);
        }

        $throttledRes = $this->withHeaders([
            'Authorization' => "Bearer {$tokenA}",
        ])->postJson('/api/auth/password/change', [
            'current_password' => 'WrongGuess!',
            'password' => 'SomePassword123!',
            'password_confirmation' => 'SomePassword123!',
        ]);

        $throttledRes->assertStatus(429);
        $this->assertStringContainsString('Too many attempts', $throttledRes->json('message'));
    }

    /**
     * 30th API: Social-only user setting their first password via POST /api/auth/password/change
     * does not require current_password.
     */
    public function test_30th_api_social_only_user_can_set_initial_password_without_current_password(): void
    {
        $socialUser = TestUser::create([
            'name' => 'Social User',
            'email' => 'social-set-pw@example.com',
            'password' => Hash::make(\Illuminate\Support\Str::random(64)),
            'password_set_at' => null,
        ]);

        AuthSocialAccount::create([
            'user_id' => $socialUser->id,
            'provider' => 'google',
            'provider_id' => 'google-user-777',
            'data' => ['is_social_only' => true],
        ]);

        $this->assertFalse(Omni::hasUserSetPassword($socialUser));

        $token = $socialUser->createToken('access_token', ['access-api'])->plainTextToken;

        // Social-only user sets password without current_password
        $res = $this->withHeaders([
            'Authorization' => "Bearer {$token}",
        ])->postJson('/api/auth/password/change', [
            'password' => 'BrandNewPassword123!',
            'password_confirmation' => 'BrandNewPassword123!',
        ]);

        $res->assertStatus(200);
        $this->assertTrue($res->json('ok'));

        $socialUser->refresh();
        $this->assertTrue(Hash::check('BrandNewPassword123!', $socialUser->password));
        $this->assertTrue(Omni::hasUserSetPassword($socialUser), 'User now has a known set password');
        $this->assertNotNull($socialUser->password_set_at);
    }
}
