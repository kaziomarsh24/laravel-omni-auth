<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Tests;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\RateLimiter;
use KaziOmar\OmniAuth\Facades\Omni;
use KaziOmar\OmniAuth\Models\AuthDevice;
use KaziOmar\OmniAuth\Models\AuthSocialAccount;
use KaziOmar\OmniAuth\Models\AuthTwoFactor;
use Laravel\Sanctum\PersonalAccessToken;

class ThirdReviewAuditTest extends TestCase
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
    }

    /**
     * N1 [Critical]: User with password who links a social account cannot delete account without password.
     */
    public function test_n1_account_deletion_with_linked_social_strictly_requires_password(): void
    {
        $user = TestUser::create([
            'name' => 'Password User',
            'email' => 'pw-social@example.com',
            'password' => Hash::make('SecretPassword123!'),
            'email_verified_at' => now(),
            'password_set_at' => now(),
        ]);

        // Link a Google account
        AuthSocialAccount::create([
            'user_id' => $user->id,
            'provider' => 'google',
            'provider_id' => 'google-user-999',
        ]);

        $token = $user->createToken('access_token', ['access-api'])->plainTextToken;

        // Attacker attempts account deletion without password confirmation
        $res = $this->withHeaders([
            'Authorization' => "Bearer {$token}",
        ])->deleteJson('/api/auth/account', []);

        $res->assertStatus(422);
        $this->assertStringContainsString('Incorrect password confirmation', $res->json('message'));
        $this->assertDatabaseHas('users', ['id' => $user->id]);

        // Legitimate user provides correct password
        $validRes = $this->withHeaders([
            'Authorization' => "Bearer {$token}",
        ])->deleteJson('/api/auth/account', [
            'password' => 'SecretPassword123!',
        ]);

        $validRes->assertStatus(200);
        $this->assertDatabaseMissing('users', ['id' => $user->id]);
    }

    /**
     * N1 & N9: Pure social-only user can delete account and setup 2FA without password.
     */
    public function test_n1_and_n9_social_only_user_can_delete_and_setup_2fa_without_password(): void
    {
        Http::fake([
            'https://oauth2.googleapis.com/tokeninfo*' => Http::response([
                'aud' => 'test-client-id.apps.googleusercontent.com',
                'sub' => 'google-pure-social-123',
                'email' => 'pure-social@example.com',
                'email_verified' => 'true',
                'name' => 'Pure Social User',
            ], 200),
        ]);

        // 1. Social signup
        $exchangeRes = $this->postJson('/api/auth/social/exchange', [
            'provider' => 'google',
            'id_token' => 'mock-google-token',
        ], self::MOBILE_HEADER);

        $exchangeRes->assertStatus(200);
        $accessToken = $exchangeRes->json('data.access_token');
        $user = TestUser::where('email', 'pure-social@example.com')->first();
        $this->assertNotNull($user);
        $this->assertFalse(Omni::hasUserSetPassword($user));

        // 2. N9: Pure social user can initiate 2FA setup without password
        $setupRes = $this->withHeaders([
            'Authorization' => "Bearer {$accessToken}",
        ])->postJson('/api/auth/2fa/setup', []);

        $setupRes->assertStatus(200);
        $this->assertTrue($setupRes->json('ok'));
        $this->assertNotEmpty($setupRes->json('data.secret'));

        // 3. N1: Pure social user can delete account without password (Apple Guideline 5.1.1(v))
        $deleteRes = $this->withHeaders([
            'Authorization' => "Bearer {$accessToken}",
        ])->deleteJson('/api/auth/account', []);

        $deleteRes->assertStatus(200);
        $this->assertDatabaseMissing('users', ['id' => $user->id]);
    }

    /**
     * N2 [High]: Logging in multiple times on same device ID revokes orphaned tokens.
     */
    public function test_n2_multiple_logins_on_same_device_id_do_not_leave_orphaned_refresh_tokens(): void
    {
        $user = TestUser::create([
            'name' => 'Device User',
            'email' => 'device-user@example.com',
            'password' => Hash::make('Password123!'),
            'email_verified_at' => now(),
            'password_set_at' => now(),
        ]);

        $headers = array_merge(self::MOBILE_HEADER, ['X-Device-ID' => 'shared_phone_uuid']);

        // First login
        $login1 = $this->postJson('/api/auth/login', [
            'email' => 'device-user@example.com',
            'password' => 'Password123!',
        ], $headers);
        $login1->assertStatus(200);
        $refresh1 = $login1->json('data.refresh_token');

        // Second login on same device ID
        $login2 = $this->postJson('/api/auth/login', [
            'email' => 'device-user@example.com',
            'password' => 'Password123!',
        ], $headers);
        $login2->assertStatus(200);
        $refresh2 = $login2->json('data.refresh_token');

        // The first refresh token must have been revoked
        $refreshAttempt1 = $this->postJson('/api/auth/refresh', [
            'refresh_token' => $refresh1,
        ], $headers);
        $this->assertEquals(401, $refreshAttempt1->status());

        // The second refresh token is valid
        $refreshAttempt2 = $this->postJson('/api/auth/refresh', [
            'refresh_token' => $refresh2,
        ], $headers);
        $this->assertEquals(200, $refreshAttempt2->status());
    }

    /**
     * N2: Single-device logout revokes paired refresh token even if not passed in body.
     */
    public function test_n2_single_device_logout_revokes_paired_refresh_token_without_body(): void
    {
        $user = TestUser::create([
            'name' => 'Logout User',
            'email' => 'logout-user@example.com',
            'password' => Hash::make('Password123!'),
            'email_verified_at' => now(),
            'password_set_at' => now(),
        ]);

        $headers = array_merge(self::MOBILE_HEADER, ['X-Device-ID' => 'logout_phone_uuid']);

        $login = $this->postJson('/api/auth/login', [
            'email' => 'logout-user@example.com',
            'password' => 'Password123!',
        ], $headers);
        $login->assertStatus(200);
        $accessToken = $login->json('data.access_token');
        $refreshToken = $login->json('data.refresh_token');

        // Logout sending ONLY Authorization Bearer header, NO refresh token in body
        $logout = $this->withHeaders([
            'Authorization' => "Bearer {$accessToken}",
            'X-Device-ID' => 'logout_phone_uuid',
        ])->postJson('/api/auth/logout', []);
        $logout->assertStatus(200);

        // Attempting to use the refresh token must fail with 401
        $refreshAttempt = $this->postJson('/api/auth/refresh', [
            'refresh_token' => $refreshToken,
        ], $headers);
        $this->assertEquals(401, $refreshAttempt->status());
    }

    /**
     * N3 [Medium]: Dynamic dummy hash prevents crash/500 on non-existent users with Argon2 driver.
     */
    public function test_n3_dummy_hash_does_not_throw_500_on_nonexistent_users(): void
    {
        $res = $this->postJson('/api/auth/login', [
            'email' => 'nonexistent_user_9999@example.com',
            'password' => 'SomePassword123!',
        ]);

        $res->assertStatus(401);
        $this->assertEquals('Invalid credentials.', $res->json('message'));
    }

    /**
     * N4 [Medium]: Pre-hijacking attacker 2FA is purged upon verified social claim.
     */
    public function test_n4_pre_hijacking_attacker_2fa_is_purged_upon_verified_social_claim(): void
    {
        // Attacker creates unverified account with 2FA
        $attackerAccount = TestUser::create([
            'name' => 'Attacker',
            'email' => 'victim-hijack@example.com',
            'password' => Hash::make('AttackerSecretPassword!'),
            'email_verified_at' => null, // UNVERIFIED
        ]);

        AuthTwoFactor::create([
            'user_id' => $attackerAccount->id,
            'secret' => Omni::twoFactor()->generateSecret(),
            'confirmed_at' => now(),
        ]);

        Http::fake([
            'https://oauth2.googleapis.com/tokeninfo*' => Http::response([
                'aud' => 'test-client-id.apps.googleusercontent.com',
                'sub' => 'google-victim-sub-123',
                'email' => 'victim-hijack@example.com',
                'email_verified' => 'true',
                'name' => 'Real Victim',
            ], 200),
        ]);

        // Victim logs in via verified Google OAuth
        $res = $this->postJson('/api/auth/social/exchange', [
            'provider' => 'google',
            'id_token' => 'mock-google-token',
        ], self::MOBILE_HEADER);

        $res->assertStatus(200);
        // Attacker's 2FA must have been purged, so victim is NOT blocked by requires_2fa
        $this->assertNull($res->json('data.requires_2fa'));
        $this->assertNotEmpty($res->json('data.access_token'));
        $this->assertDatabaseMissing('auth_two_factor', ['user_id' => $attackerAccount->id]);
    }

    /**
     * N5 [Medium]: Re-authentication endpoints enforce brute-force rate limiting.
     */
    public function test_n5_reauth_endpoints_are_rate_limited(): void
    {
        $user = TestUser::create([
            'name' => 'Victim',
            'email' => 'victim-reauth@example.com',
            'password' => Hash::make('CorrectPassword123!'),
            'email_verified_at' => now(),
            'password_set_at' => now(),
        ]);

        $token = $user->createToken('access_token', ['access-api'])->plainTextToken;

        // 5 consecutive failed attempts on 2FA setup password confirmation
        for ($i = 0; $i < 5; $i++) {
            $res = $this->withHeaders([
                'Authorization' => "Bearer {$token}",
            ])->postJson('/api/auth/2fa/setup', ['password' => 'WrongPassword!']);
            $res->assertStatus(422);
        }

        // 6th attempt should be blocked with 429
        $throttledRes = $this->withHeaders([
            'Authorization' => "Bearer {$token}",
        ])->postJson('/api/auth/2fa/setup', ['password' => 'WrongPassword!']);
        $throttledRes->assertStatus(429);
        $this->assertStringContainsString('Too many attempts', $throttledRes->json('message'));
    }

    /**
     * N6 [Medium]: Email case normalization:
     * - Registration unique validation rule validates normalized email (no SQL 500).
     * - Mixed casing login works seamlessly.
     */
    public function test_n6_email_case_normalization_in_registration_and_login(): void
    {
        // 1. Register with mixed case
        $reg = $this->postJson('/api/auth/register', [
            'name' => 'Case User',
            'email' => 'MixedCase@Example.com',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
        ]);
        $reg->assertStatus(201);

        // 2. Registering with uppercase of same email returns 422, NOT SQL 500
        $dup = $this->postJson('/api/auth/register', [
            'name' => 'Duplicate User',
            'email' => 'MIXEDCASE@EXAMPLE.COM',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
        ]);
        $dup->assertStatus(422);
        $this->assertStringContainsString('has already been taken', $dup->json('errors.email.0'));

        // 3. Login with mixed case works
        $loginMixed = $this->postJson('/api/auth/login', [
            'email' => 'MixedCase@Example.com',
            'password' => 'Password123!',
        ], self::MOBILE_HEADER);
        $loginMixed->assertStatus(200);

        // 4. Login with uppercase works
        $loginUpper = $this->postJson('/api/auth/login', [
            'email' => 'MIXEDCASE@EXAMPLE.COM',
            'password' => 'Password123!',
        ], self::MOBILE_HEADER);
        $loginUpper->assertStatus(200);
    }

    /**
     * N7 [Medium]: Sanctum global hook does not reject custom application tokens with other abilities (e.g. ['read']).
     */
    public function test_n7_sanctum_hook_allows_tokens_with_custom_abilities(): void
    {
        $user = TestUser::create([
            'name' => 'Custom Token User',
            'email' => 'custom-token@example.com',
            'password' => Hash::make('Password123!'),
            'email_verified_at' => now(),
        ]);

        $customToken = $user->createToken('custom_app_token', ['read'])->plainTextToken;

        // Accessing auth:sanctum / omni.auth protected route with ['read'] ability
        $res = $this->withHeaders([
            'Authorization' => "Bearer {$customToken}",
        ])->getJson('/api/auth/devices');

        $res->assertStatus(200);
    }

    /**
     * N10: omni:prune-tokens with --days option runs successfully without InvalidOptionException.
     */
    public function test_n10_prune_tokens_command_supports_days_option(): void
    {
        $exitCode = Artisan::call('omni:prune-tokens', ['--days' => 30]);
        $this->assertEquals(0, $exitCode);

        $exitCodeHours = Artisan::call('omni:prune-tokens', ['--hours' => 24]);
        $this->assertEquals(0, $exitCodeHours);
    }
}
