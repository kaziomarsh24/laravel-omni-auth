<?php

namespace KaziOmar\OmniAuth\Tests;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use KaziOmar\OmniAuth\Events\EmailVerificationRequested;
use KaziOmar\OmniAuth\Events\PasswordResetOtpRequested;
use KaziOmar\OmniAuth\Facades\Omni;
use KaziOmar\OmniAuth\Models\AuthDevice;
use KaziOmar\OmniAuth\Models\AuthTwoFactor;
use Laravel\Sanctum\PersonalAccessToken;

class SecurityResidualsTest extends TestCase
{
    private const MOBILE_HEADER = ['X-Client-Type' => 'mobile'];
    protected TestUser $victim;

    protected function setUp(): void
    {
        parent::setUp();

        $this->victim = TestUser::create([
            'name' => 'Victim',
            'email' => 'victim@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        config()->set('app.url', 'https://app.example.com');
        config()->set('omni-auth.social.providers.apple', ['client_id' => 'com.example.app']);
        config()->set('omni-auth.social.providers.google', [
            'client_id' => 'g-client',
            'client_secret' => 'secret',
            'mobile_client_ids' => ['g-client'],
        ]);
        config()->set('omni-auth.features', array_merge(config('omni-auth.features'), [
            \KaziOmar\OmniAuth\Features::magicLoginLink(),
        ]));
    }

    public function test_apple_signature_and_algorithm_validation(): void
    {
        $b64 = fn($a) => rtrim(strtr(base64_encode(is_array($a) ? json_encode($a) : $a), '+/', '-_'), '=');
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $det = openssl_pkey_get_details($key);
        $jwk = ['kty' => 'RSA', 'kid' => 'k1', 'n' => $b64($det['rsa']['n']), 'e' => $b64($det['rsa']['e'])];

        $mk = function ($k, $claims = []) use ($b64) {
            $h = $b64(['alg' => 'RS256', 'kid' => 'k1']);
            $p = $b64(array_merge([
                'iss' => 'https://appleid.apple.com',
                'aud' => 'com.example.app',
                'sub' => 'a1',
                'email' => 'victim@example.com',
                'email_verified' => 'true',
                'exp' => time() + 600,
            ], $claims));
            openssl_sign("$h.$p", $sig, $k, OPENSSL_ALGO_SHA256);
            return "$h.$p." . $b64($sig);
        };

        // 1. Properly signed Apple token succeeds
        Http::fake(['appleid.apple.com/auth/keys' => Http::response(['keys' => [$jwk]])]);
        $okRes = $this->postJson('/api/auth/social/exchange', [
            'provider' => 'apple',
            'id_token' => $mk($key),
        ], self::MOBILE_HEADER);
        $okRes->assertStatus(200);

        // 2. Token signed with attacker's own RSA key fails with 400
        $evilKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $badRes = $this->postJson('/api/auth/social/exchange', [
            'provider' => 'apple',
            'id_token' => $mk($evilKey),
        ], self::MOBILE_HEADER);
        $badRes->assertStatus(400);
        $this->assertStringContainsString('signature verification failed', $badRes->json('message'));

        // 3. HS256 Key confusion attempt is blocked with 400
        $h = $b64(['alg' => 'HS256', 'kid' => 'k1']);
        $p = $b64(['iss' => 'https://appleid.apple.com', 'aud' => 'com.example.app', 'sub' => 'a1', 'email' => 'victim@example.com', 'exp' => time() + 600]);
        $hsToken = "$h.$p." . $b64(hash_hmac('sha256', "$h.$p", 'secret', true));
        $hsRes = $this->postJson('/api/auth/social/exchange', [
            'provider' => 'apple',
            'id_token' => $hsToken,
        ], self::MOBILE_HEADER);
        $hsRes->assertStatus(400);
        $this->assertStringContainsString('RS256 algorithm', $hsRes->json('message'));
    }

    public function test_apple_jwks_outage_does_not_cache_empty_keys(): void
    {
        Cache::flush();
        $b64 = fn($a) => rtrim(strtr(base64_encode(is_array($a) ? json_encode($a) : $a), '+/', '-_'), '=');
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $det = openssl_pkey_get_details($key);
        $jwk = ['kty' => 'RSA', 'kid' => 'k1', 'n' => $b64($det['rsa']['n']), 'e' => $b64($det['rsa']['e'])];

        $h = $b64(['alg' => 'RS256', 'kid' => 'k1']);
        $p = $b64(['iss' => 'https://appleid.apple.com', 'aud' => 'com.example.app', 'sub' => 'a1', 'email' => 'victim@example.com', 'email_verified' => 'true', 'exp' => time() + 600]);
        openssl_sign("$h.$p", $sig, $key, OPENSSL_ALGO_SHA256);
        $tok = "$h.$p." . $b64($sig);

        // Apple is down initially (500), then recovers (200)
        Http::fake([
            'appleid.apple.com/auth/keys' => Http::sequence()
                ->push('Server Error', 500)
                ->push(['keys' => [$jwk]], 200),
        ]);

        $res1 = $this->postJson('/api/auth/social/exchange', ['provider' => 'apple', 'id_token' => $tok], self::MOBILE_HEADER);
        $res1->assertStatus(400);

        $res2 = $this->postJson('/api/auth/social/exchange', ['provider' => 'apple', 'id_token' => $tok], self::MOBILE_HEADER);

        // 2nd attempt MUST succeed and not be poisoned by a 24h empty cache
        $res2->assertStatus(200);
    }

    public function test_oauth_callback_strictly_requires_state_parameter(): void
    {
        Http::fake([
            'oauth2.googleapis.com/token' => Http::response(['access_token' => 'mock-token']),
            'www.googleapis.com/oauth2/v3/userinfo' => Http::response([
                'sub' => 'g-attacker',
                'email' => 'victim@example.com',
                'email_verified' => true,
            ]),
        ]);

        // OAuth callback with NO state parameter MUST return 400
        $response = $this->getJson('/api/auth/social/google/callback?code=ATTACKER_CODE');
        $response->assertStatus(400);
        $this->assertStringContainsString('Missing required OAuth state', $response->json('message'));
    }

    public function test_pre_hijacked_account_password_is_invalidated_upon_social_link(): void
    {
        // 1. Attacker pre-registers victim's email with their own password
        TestUser::where('email', 'victim@example.com')->delete();
        $unverifiedUser = TestUser::create([
            'name' => 'Unverified Target',
            'email' => 'victim@example.com',
            'password' => Hash::make('AttackerPassword123!'),
            'email_verified_at' => null, // Unverified
        ]);

        // 2. Real victim signs in with verified Google account
        Http::fake([
            'oauth2.googleapis.com/tokeninfo*' => Http::response([
                'aud' => 'g-client',
                'sub' => 'google-real-victim',
                'email' => 'victim@example.com',
                'email_verified' => 'true',
                'exp' => time() + 600,
            ], 200),
        ]);

        $exchangeRes = $this->postJson('/api/auth/social/exchange', [
            'provider' => 'google',
            'id_token' => 'real-google-token',
        ], self::MOBILE_HEADER);
        $exchangeRes->assertStatus(200);

        // 3. Attacker tries to log in with their pre-set password -> MUST FAIL with 401
        $attackerLoginRes = $this->postJson('/api/auth/login', [
            'email' => 'victim@example.com',
            'password' => 'AttackerPassword123!',
        ], self::MOBILE_HEADER);

        $attackerLoginRes->assertStatus(401);
    }

    public function test_redirect_url_validator_rejects_backslash_and_subdomain_tricks(): void
    {
        $manager = Omni::passwordReset();

        // Plain external domain -> reject
        $this->expectException(\Illuminate\Validation\ValidationException::class);
        $manager->validateRedirectUrl('https://evil.com/steal');
    }

    public function test_redirect_url_validator_backslash_trick_rejected(): void
    {
        $manager = Omni::passwordReset();

        $this->expectException(\Illuminate\Validation\ValidationException::class);
        $manager->validateRedirectUrl('https://evil.com\\.app.example.com/x');
    }

    public function test_redirect_url_validator_userinfo_trick_rejected(): void
    {
        $manager = Omni::passwordReset();

        $this->expectException(\Illuminate\Validation\ValidationException::class);
        $manager->validateRedirectUrl('http://evil.com\\@localhost/x');
    }

    public function test_public_email_verification_route_blocks_otp_bruteforce_and_enumeration(): void
    {
        $cap = null;
        Event::listen(EmailVerificationRequested::class, function ($e) use (&$cap) {
            $cap = $e;
        });

        Omni::passwordReset()->sendEmailVerification($this->victim);
        $otp = $cap->otp;

        // 1. Non-existent ID without valid signature returns 422 (same as invalid signature)
        $unknownRes = $this->postJson('/api/auth/email/verify/99999/invalid-hash', [
            'otp' => '000000',
        ]);
        $unknownRes->assertStatus(422);

        // 2. Existing ID without valid signature also returns 422 (no ID enumeration)
        $existRes = $this->postJson("/api/auth/email/verify/{$this->victim->id}/invalid-hash", [
            'otp' => '000000',
        ]);
        $existRes->assertStatus(422);

        // Both return identical status code and message
        $this->assertEquals($unknownRes->json('message'), $existRes->json('message'));

        // 3. Authenticated endpoint rate limits failed OTP attempts
        $this->actingAs($this->victim, 'sanctum');

        for ($i = 0; $i < 5; $i++) {
            $fail = $this->postJson('/api/auth/email/verify', ['otp' => '99999' . $i]);
            $fail->assertStatus(422);
        }

        // 6th attempt is blocked
        $blocked = $this->postJson('/api/auth/email/verify', ['otp' => (string) $otp]);
        $blocked->assertStatus(422);
        $this->assertNull($this->victim->fresh()->email_verified_at);
    }

    public function test_refresh_token_cannot_authenticate_on_vanilla_sanctum_routes(): void
    {
        Route::middleware('auth:sanctum')->get('/probe/sanctum-plain', function () {
            return response()->json(['user_id' => auth('sanctum')->id()]);
        });

        $loginRes = $this->postJson('/api/auth/login', [
            'email' => 'victim@example.com',
            'password' => 'Password123!',
        ], self::MOBILE_HEADER);

        $refreshToken = $loginRes->json('data.refresh_token');
        $this->assertNotEmpty($refreshToken);

        // Access vanilla sanctum route with refresh token
        $response = $this->withHeaders([
            'Authorization' => 'Bearer ' . $refreshToken,
            'Accept' => 'application/json',
        ])->getJson('/probe/sanctum-plain');

        // MUST be 401 unauthenticated
        $response->assertStatus(401);
    }

    public function test_device_revocation_invalidates_associated_refresh_token(): void
    {
        $loginRes = $this->postJson('/api/auth/login', [
            'email' => 'victim@example.com',
            'password' => 'Password123!',
        ], array_merge(self::MOBILE_HEADER, ['X-Device-ID' => 'test-device-1']));

        $accessToken = $loginRes->json('data.access_token');
        $refreshToken = $loginRes->json('data.refresh_token');

        // Get device ID
        $deviceListRes = $this->withHeaders([
            'Authorization' => "Bearer {$accessToken}",
        ])->getJson('/api/auth/devices');

        $deviceId = $deviceListRes->json('data.devices.0.id');
        $this->assertNotNull($deviceId);

        // Revoke device
        $deleteRes = $this->withHeaders([
            'Authorization' => "Bearer {$accessToken}",
        ])->deleteJson("/api/auth/devices/{$deviceId}");
        $deleteRes->assertStatus(200);

        // Attempting to refresh using revoked device's refresh token MUST FAIL with 401
        $refreshRes = $this->postJson('/api/auth/refresh', [
            'refresh_token' => $refreshToken,
        ], self::MOBILE_HEADER);

        $refreshRes->assertStatus(401);
    }

    public function test_registration_mass_assignment_case_variants_strictly_guarded(): void
    {
        $res = $this->postJson('/api/auth/register', [
            'name' => 'Attacker',
            'email' => 'mal@example.com',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
            'Is_Admin' => 1,
            'ROLE' => 'superadmin',
            'is_STAFF' => 1,
        ], self::MOBILE_HEADER);

        $res->assertStatus(201);

        $user = DB::table('users')->where('email', 'mal@example.com')->first();
        $this->assertNotNull($user);
        $this->assertEquals(0, (int) $user->is_admin);
        $this->assertNull($user->role);
    }

    public function test_registration_normalizes_email_to_lowercase(): void
    {
        $res = $this->postJson('/api/auth/register', [
            'name' => 'Mixed Email User',
            'email' => 'MixedCase@Example.com',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
        ], self::MOBILE_HEADER);

        $res->assertStatus(201);

        $user = DB::table('users')->where('email', 'mixedcase@example.com')->first();
        $this->assertNotNull($user);

        // Requesting password reset with any case finds the user and dispatches OTP
        Event::fake([PasswordResetOtpRequested::class]);
        $forgotRes = $this->postJson('/api/auth/forgot-password', [
            'email' => 'MixedCase@Example.com',
        ]);
        $forgotRes->assertStatus(200);
        Event::assertDispatched(PasswordResetOtpRequested::class);
    }

    public function test_2fa_setup_requires_reauthentication_even_for_first_time_setup(): void
    {
        $token = $this->victim->createToken('access_token', ['access-api'])->plainTextToken;

        // Attacker with stolen access token attempts to set up 2FA without password
        $setupRes = $this->withHeaders([
            'Authorization' => "Bearer {$token}",
        ])->postJson('/api/auth/2fa/setup', []);

        $setupRes->assertStatus(422);
        $this->assertStringContainsString('Password confirmation is required', $setupRes->json('message'));
    }

    public function test_2fa_recovery_codes_requires_reauthentication(): void
    {
        $token = $this->victim->createToken('access_token', ['access-api'])->plainTextToken;
        $secret = Omni::twoFactor()->generateSecret();
        AuthTwoFactor::create([
            'user_id' => $this->victim->id,
            'secret' => $secret,
            'confirmed_at' => now(),
        ]);

        $res = $this->withHeaders([
            'Authorization' => "Bearer {$token}",
        ])->postJson('/api/auth/2fa/recovery-codes', []);

        $res->assertStatus(422);
        $this->assertStringContainsString('confirmation is required', $res->json('message'));
    }

    public function test_2fa_disable_is_rate_limited(): void
    {
        $token = $this->victim->createToken('access_token', ['access-api'])->plainTextToken;
        $secret = Omni::twoFactor()->generateSecret();
        AuthTwoFactor::create([
            'user_id' => $this->victim->id,
            'secret' => $secret,
            'confirmed_at' => now(),
        ]);

        for ($i = 0; $i < 5; $i++) {
            $res = $this->withHeaders([
                'Authorization' => "Bearer {$token}",
            ])->postJson('/api/auth/2fa/disable', ['password' => "wrong-pass-{$i}"]);
            $res->assertStatus(422);
        }

        // 6th attempt triggers 429
        $blocked = $this->withHeaders([
            'Authorization' => "Bearer {$token}",
        ])->postJson('/api/auth/2fa/disable', ['password' => 'wrong-pass-6']);

        $blocked->assertStatus(429);
    }

    public function test_2fa_challenge_farming_locked_per_user(): void
    {
        $secret = Omni::twoFactor()->generateSecret();
        AuthTwoFactor::create([
            'user_id' => $this->victim->id,
            'secret' => $secret,
            'confirmed_at' => now(),
        ]);

        for ($i = 0; $i < 5; $i++) {
            $res = $this->postJson('/api/auth/login', [
                'email' => 'victim@example.com',
                'password' => 'Password123!',
            ], self::MOBILE_HEADER);
            $res->assertStatus(200);
        }

        // 6th consecutive login challenge attempt without completing 2FA triggers 429
        $farmingBlocked = $this->postJson('/api/auth/login', [
            'email' => 'victim@example.com',
            'password' => 'Password123!',
        ], self::MOBILE_HEADER);

        $farmingBlocked->assertStatus(429);
        $this->assertStringContainsString('Too many two-factor challenges', $farmingBlocked->json('message'));
    }

    public function test_social_only_user_can_delete_account_without_password(): void
    {
        Http::fake([
            'oauth2.googleapis.com/tokeninfo*' => Http::response([
                'aud' => 'g-client',
                'sub' => 'g-social-only-user',
                'email' => 'socialonly@example.com',
                'email_verified' => 'true',
                'name' => 'Social Only',
                'exp' => time() + 600,
            ], 200),
        ]);

        $exchangeRes = $this->postJson('/api/auth/social/exchange', [
            'provider' => 'google',
            'id_token' => 'mock-google-token',
        ], self::MOBILE_HEADER);

        $accessToken = $exchangeRes->json('data.access_token');
        $this->assertNotEmpty($accessToken);

        // Delete account without password
        $delRes = $this->withHeaders([
            'Authorization' => "Bearer {$accessToken}",
        ])->deleteJson('/api/auth/account');

        $delRes->assertStatus(200);
        $this->assertTrue($delRes->json('ok'));
    }

    public function test_array_input_on_login_returns_422_not_500(): void
    {
        $res = $this->postJson('/api/auth/login', [
            'email' => ['injected_array'],
            'password' => 'Password123!',
        ], self::MOBILE_HEADER);

        $res->assertStatus(422);
    }

    public function test_social_redirect_route_is_rate_limited_against_cache_flooding(): void
    {
        Cache::flush();

        // 30 requests within 1 minute are allowed
        for ($i = 0; $i < 30; $i++) {
            $res = $this->getJson('/api/auth/social/google/redirect');
            $this->assertEquals(200, $res->status());
        }

        // 31st request triggers rate limiter (HTTP 429 Too Many Requests)
        $blocked = $this->getJson('/api/auth/social/google/redirect');
        $this->assertEquals(429, $blocked->status());
        $this->assertStringContainsString('Too many social redirect requests', $blocked->json('message'));
    }
}
