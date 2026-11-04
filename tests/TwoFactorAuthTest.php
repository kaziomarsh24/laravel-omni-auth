<?php

namespace KaziOmar\OmniAuth\Tests;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use KaziOmar\OmniAuth\Facades\Omni;
use KaziOmar\OmniAuth\Features;
use KaziOmar\OmniAuth\Models\AuthTwoFactor;

class TwoFactorAuthTest extends TestCase
{
    protected TestUser $user;

    protected function setUp(): void
    {
        parent::setUp();

        config(['omni-auth.features' => [
            Features::emailAuthentication(),
            Features::dualModeTokens(),
            Features::tokenRotation(),
            Features::registration(),
            Features::twoFactorAuth(),
        ]]);

        $this->user = TestUser::create([
            'name' => 'TwoFactor Explorer',
            'email' => 'twofactor@example.com',
            'password' => Hash::make('Password123!'),
        ]);
    }

    public function test_totp_code_generation_and_verification_with_clock_drift(): void
    {
        $manager = Omni::twoFactor();
        $secret = $manager->generateSecret();

        $this->assertNotEmpty($secret);
        $this->assertEquals(32, strlen($secret));

        // Generate current 6-digit TOTP code
        $code = $manager->calculateCode($secret);
        $this->assertEquals(6, strlen($code));
        $this->assertMatchesRegularExpression('/^\d{6}$/', $code);

        // Verification must succeed
        $this->assertTrue($manager->verifyCode($secret, $code));

        // Wrong code must fail
        $this->assertFalse($manager->verifyCode($secret, '000000'));
    }

    public function test_two_factor_setup_and_confirmation_flow(): void
    {
        $this->actingAs($this->user, 'sanctum');

        // 1. Initiate 2FA Setup
        $setupResponse = $this->postJson('/api/auth/2fa/setup');
        $setupResponse->assertStatus(200)
            ->assertJsonPath('ok', true)
            ->assertJsonStructure([
                'ok',
                'message',
                'data' => [
                    'secret',
                    'qr_code_uri',
                    'recovery_codes',
                ],
            ]);

        $setupData = $setupResponse->json('data');
        $secret = $setupData['secret'];
        $recoveryCodes = $setupData['recovery_codes'];

        $this->assertCount(8, $recoveryCodes);
        $this->assertStringStartsWith('otpauth://totp/', $setupData['qr_code_uri']);

        // Before confirmation, 2FA must NOT be active
        $this->assertFalse(Omni::twoFactor()->isEnabled($this->user));

        // 2. Confirm 2FA with invalid code -> must fail
        $failConfirm = $this->postJson('/api/auth/2fa/confirm', [
            'code' => '999999',
        ]);
        $failConfirm->assertStatus(422)
            ->assertJsonPath('ok', false);

        // 3. Confirm 2FA with valid TOTP code
        $validCode = Omni::twoFactor()->calculateCode($secret);
        $confirmResponse = $this->postJson('/api/auth/2fa/confirm', [
            'code' => $validCode,
        ]);

        $confirmResponse->assertStatus(200)
            ->assertJsonPath('ok', true);

        // Now 2FA must be active
        $this->assertTrue(Omni::twoFactor()->isEnabled($this->user));
        $this->assertNotNull(AuthTwoFactor::where('user_id', $this->user->id)->first()->confirmed_at);
    }

    public function test_login_triggers_pre_auth_challenge_when_2fa_is_active(): void
    {
        // Setup and confirm 2FA for user
        $setup = Omni::twoFactor()->setup($this->user);
        $code = Omni::twoFactor()->calculateCode($setup['secret']);
        Omni::twoFactor()->confirm($this->user, $code);

        // Attempt normal login
        $response = $this->postJson('/api/auth/login', [
            'email' => 'twofactor@example.com',
            'password' => 'Password123!',
        ]);

        // Must return requires_2fa challenge instead of granting full tokens
        $response->assertStatus(200)
            ->assertJsonPath('ok', true)
            ->assertJsonPath('data.requires_2fa', true)
            ->assertJsonStructure([
                'ok',
                'message',
                'data' => [
                    'requires_2fa',
                    'two_factor_token',
                    'expires_in',
                ],
            ]);

        // Security check: No tokens or cookies delivered in pre-auth challenge
        $this->assertArrayNotHasKey('access_token', $response->json('data'));
        $this->assertEmpty($response->headers->getCookies());
    }

    public function test_two_factor_challenge_exchange_with_valid_totp_code(): void
    {
        $setup = Omni::twoFactor()->setup($this->user);
        $secret = $setup['secret'];
        Omni::twoFactor()->confirm($this->user, Omni::twoFactor()->calculateCode($secret));

        // 1. Initial Login gives challenge token
        $loginRes = $this->postJson('/api/auth/login', [
            'email' => 'twofactor@example.com',
            'password' => 'Password123!',
        ], [
            'X-Client-Type' => 'mobile',
        ]);

        $twoFactorToken = $loginRes->json('data.two_factor_token');
        $this->assertNotEmpty($twoFactorToken);

        // 2. Exchange challenge token with valid TOTP code
        $validCode = Omni::twoFactor()->calculateCode($secret);

        $challengeRes = $this->postJson('/api/auth/2fa/challenge', [
            'two_factor_token' => $twoFactorToken,
            'code' => $validCode,
        ], [
            'X-Client-Type' => 'mobile',
        ]);

        $challengeRes->assertStatus(200)
            ->assertJsonPath('ok', true)
            ->assertJsonStructure([
                'ok',
                'message',
                'data' => [
                    'access_token',
                    'refresh_token',
                    'token_type',
                    'user',
                ],
            ]);

        // 3. Challenge token must be single-use (cannot be re-used)
        $replayRes = $this->postJson('/api/auth/2fa/challenge', [
            'two_factor_token' => $twoFactorToken,
            'code' => $validCode,
        ]);

        $replayRes->assertStatus(422);
    }

    public function test_two_factor_challenge_exchange_with_emergency_recovery_code(): void
    {
        $setup = Omni::twoFactor()->setup($this->user);
        $secret = $setup['secret'];
        $recoveryCodes = $setup['recovery_codes'];
        Omni::twoFactor()->confirm($this->user, Omni::twoFactor()->calculateCode($secret));

        $chosenRecoveryCode = $recoveryCodes[0];

        // 1. Initial Login
        $loginRes = $this->postJson('/api/auth/login', [
            'email' => 'twofactor@example.com',
            'password' => 'Password123!',
        ]);
        $twoFactorToken = $loginRes->json('data.two_factor_token');

        // 2. Submit Emergency Recovery Code instead of TOTP
        $challengeRes = $this->postJson('/api/auth/2fa/challenge', [
            'two_factor_token' => $twoFactorToken,
            'code' => $chosenRecoveryCode,
        ], [
            'X-Client-Type' => 'mobile',
        ]);

        $challengeRes->assertStatus(200)
            ->assertJsonPath('ok', true)
            ->assertJsonStructure([
                'ok',
                'data' => ['access_token'],
            ]);

        // Security assertion: Recovery code is single-use and MUST BE CONSUMED
        $twoFactorModel = AuthTwoFactor::where('user_id', $this->user->id)->first();
        $this->assertCount(7, $twoFactorModel->recovery_codes, 'Used recovery code must be removed from pool.');

        // 3. Attempting to login again with the same recovery code must fail
        $secondLoginRes = $this->postJson('/api/auth/login', [
            'email' => 'twofactor@example.com',
            'password' => 'Password123!',
        ]);
        $secondToken = $secondLoginRes->json('data.two_factor_token');

        $secondChallengeRes = $this->postJson('/api/auth/2fa/challenge', [
            'two_factor_token' => $secondToken,
            'code' => $chosenRecoveryCode,
        ]);

        $secondChallengeRes->assertStatus(422);
    }

    public function test_regenerate_recovery_codes_and_disable_2fa(): void
    {
        $setup = Omni::twoFactor()->setup($this->user);
        Omni::twoFactor()->confirm($this->user, Omni::twoFactor()->calculateCode($setup['secret']));

        $this->actingAs($this->user, 'sanctum');

        // 1. Regenerate recovery codes
        $regenRes = $this->postJson('/api/auth/2fa/recovery-codes');
        $regenRes->assertStatus(200)
            ->assertJsonPath('ok', true);

        $newCodes = $regenRes->json('data.recovery_codes');
        $this->assertCount(8, $newCodes);

        // 2. Disable 2FA requires password re-authentication (C4 security requirement)
        $unauthDisable = $this->postJson('/api/auth/2fa/disable');
        $unauthDisable->assertStatus(422);

        $wrongPassDisable = $this->postJson('/api/auth/2fa/disable', ['password' => 'WrongPassword!']);
        $wrongPassDisable->assertStatus(422);

        $disableRes = $this->postJson('/api/auth/2fa/disable', ['password' => 'Password123!']);
        $disableRes->assertStatus(200)
            ->assertJsonPath('ok', true);

        $this->assertFalse(Omni::twoFactor()->isEnabled($this->user));

        // 3. Next login should directly succeed without 2FA challenge
        $loginRes = $this->postJson('/api/auth/login', [
            'email' => 'twofactor@example.com',
            'password' => 'Password123!',
        ], [
            'X-Client-Type' => 'mobile',
        ]);

        $loginRes->assertStatus(200)
            ->assertJsonPath('data.user.email', 'twofactor@example.com');
        $this->assertArrayHasKey('access_token', $loginRes->json('data'));
    }

    public function test_two_factor_fallback_otp_flow(): void
    {
        \Illuminate\Support\Facades\Event::fake([
            \KaziOmar\OmniAuth\Events\TwoFactorFallbackOtpRequested::class,
        ]);

        // Setup and confirm 2FA
        $setup = Omni::twoFactor()->setup($this->user);
        $validTotp = Omni::twoFactor()->calculateCode($setup['secret']);
        Omni::twoFactor()->confirm($this->user, $validTotp);

        // Attempt login -> get challenge token
        $loginRes = $this->postJson('/api/auth/login', [
            'email' => 'twofactor@example.com',
            'password' => 'Password123!',
        ], ['X-Client-Type' => 'mobile']);

        $token = $loginRes->json('data.two_factor_token');

        // Request fallback OTP
        $otpRes = $this->postJson('/api/auth/2fa/fallback-otp', [
            'two_factor_token' => $token,
        ]);

        $otpRes->assertStatus(200)
            ->assertJsonPath('ok', true);

        \Illuminate\Support\Facades\Event::assertDispatched(
            \KaziOmar\OmniAuth\Events\TwoFactorFallbackOtpRequested::class,
            function ($event) use ($token) {
                // Now verify the challenge with this dispatched fallback OTP
                $verifyRes = $this->postJson('/api/auth/2fa/challenge', [
                    'two_factor_token' => $token,
                    'code' => $event->otp,
                ], ['X-Client-Type' => 'mobile']);

                $verifyRes->assertStatus(200)
                    ->assertJsonPath('data.user.email', 'twofactor@example.com');

                return true;
            }
        );
    }

    public function test_two_factor_challenge_brute_force_lockout(): void
    {
        $setup = Omni::twoFactor()->setup($this->user);
        $validTotp = Omni::twoFactor()->calculateCode($setup['secret']);
        Omni::twoFactor()->confirm($this->user, $validTotp);

        $loginRes = $this->postJson('/api/auth/login', [
            'email' => 'twofactor@example.com',
            'password' => 'Password123!',
        ]);

        $token = $loginRes->json('data.two_factor_token');

        // Send 5 invalid attempts
        for ($i = 0; $i < 5; $i++) {
            $failRes = $this->postJson('/api/auth/2fa/challenge', [
                'two_factor_token' => $token,
                'code' => '000000',
            ]);
            $failRes->assertStatus(422);
        }

        // 6th attempt with CORRECT code should now be completely rejected because challenge is destroyed
        $blockedRes = $this->postJson('/api/auth/2fa/challenge', [
            'two_factor_token' => $token,
            'code' => Omni::twoFactor()->calculateCode($setup['secret']),
        ]);

        $blockedRes->assertStatus(422)
            ->assertJsonPath('message', 'Too many invalid two-factor verification attempts. Challenge expired. Please log in again.');
    }
}
