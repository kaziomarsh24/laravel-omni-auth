<?php

namespace KaziOmar\OmniAuth\Tests;

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\Verified;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use KaziOmar\OmniAuth\Events\AccountDeleted;
use KaziOmar\OmniAuth\Events\EmailVerificationRequested;
use KaziOmar\OmniAuth\Events\MagicLinkRequested;
use KaziOmar\OmniAuth\Events\PasswordResetOtpRequested;
use KaziOmar\OmniAuth\Facades\Omni;
use KaziOmar\OmniAuth\Models\AuthDevice;
use KaziOmar\OmniAuth\Models\AuthSocialAccount;
use KaziOmar\OmniAuth\Models\AuthTwoFactor;

class PasswordAndVerificationTest extends TestCase
{
    protected TestUser $user;

    protected function setUp(): void
    {
        parent::setUp();

        $this->user = TestUser::create([
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => Hash::make('Secret123!@#'),
        ]);
    }

    public function test_password_reset_otp_request_and_exchange(): void
    {
        Event::fake([PasswordResetOtpRequested::class]);

        $response = $this->postJson('/api/auth/forgot-password', [
            'email' => 'john@example.com',
        ]);

        $response->assertStatus(200)
            ->assertJsonPath('ok', true);

        $capturedOtp = null;

        Event::assertDispatched(PasswordResetOtpRequested::class, function ($event) use (&$capturedOtp) {
            $capturedOtp = $event->otp;
            $this->assertEquals(6, strlen($event->otp));
            $this->assertEquals($this->user->id, $event->user->id);
            return true;
        });

        $this->assertNotNull($capturedOtp);

        // Exchange OTP for temporary reset token
        $verifyRes = $this->postJson('/api/auth/verify-reset-otp', [
            'email' => 'john@example.com',
            'otp' => $capturedOtp,
        ]);

        $verifyRes->assertStatus(200)
            ->assertJsonPath('ok', true);

        $resetToken = $verifyRes->json('data.reset_token');
        $this->assertNotEmpty($resetToken);
        $this->assertStringStartsWith('pwd_reset_', $resetToken);
    }

    public function test_password_reset_enforces_strength_and_executes_global_session_revocation(): void
    {
        Event::fake([PasswordResetOtpRequested::class, PasswordReset::class]);

        // Create an existing Sanctum token to test global session revocation
        $existingToken = $this->user->createToken('test_token');
        $this->assertEquals(1, $this->user->tokens()->count());

        // 1. Request OTP
        $this->postJson('/api/auth/forgot-password', ['email' => 'john@example.com']);

        $otp = null;
        Event::assertDispatched(PasswordResetOtpRequested::class, function ($event) use (&$otp) {
            $otp = $event->otp;
            return true;
        });

        // 2. Exchange for reset token
        $verifyRes = $this->postJson('/api/auth/verify-reset-otp', [
            'email' => 'john@example.com',
            'otp' => $otp,
        ]);
        $resetToken = $verifyRes->json('data.reset_token');

        // 3. Weak password should be rejected by strength validation
        $weakRes = $this->postJson('/api/auth/reset-password', [
            'token' => $resetToken,
            'password' => 'simple',
            'password_confirmation' => 'simple',
        ]);
        $weakRes->assertStatus(422)
            ->assertJsonPath('ok', false);

        // 4. Strong password succeeds
        $strongRes = $this->postJson('/api/auth/reset-password', [
            'token' => $resetToken,
            'password' => 'NewStrongPass#2026!',
            'password_confirmation' => 'NewStrongPass#2026!',
        ]);

        $strongRes->assertStatus(200)
            ->assertJsonPath('ok', true);

        Event::assertDispatched(PasswordReset::class);

        // 5. Assert GLOBAL SESSION REVOCATION: all active tokens deleted
        $this->assertEquals(0, $this->user->tokens()->count());

        // 6. Assert user can log in with new password and cannot with old password
        $this->assertFalse(Hash::check('Secret123!@#', $this->user->fresh()->password));
        $this->assertTrue(Hash::check('NewStrongPass#2026!', $this->user->fresh()->password));
    }

    public function test_email_verification_flow(): void
    {
        Event::fake([EmailVerificationRequested::class, Verified::class]);

        $this->assertFalse($this->user->hasVerifiedEmail());

        $this->actingAs($this->user);

        // Resend email verification
        $resendRes = $this->postJson('/api/auth/email/resend');
        $resendRes->assertStatus(200)
            ->assertJsonPath('ok', true);

        $otp = null;
        Event::assertDispatched(EmailVerificationRequested::class, function ($event) use (&$otp) {
            $otp = $event->otp;
            $this->assertNotEmpty($event->verificationUrl);
            return true;
        });

        // Verify email with OTP
        $verifyRes = $this->postJson('/api/auth/email/verify', [
            'otp' => $otp,
        ]);

        $verifyRes->assertStatus(200)
            ->assertJsonPath('ok', true);

        Event::assertDispatched(Verified::class);
        $this->assertTrue($this->user->fresh()->hasVerifiedEmail());
    }

    public function test_passwordless_magic_login_link_flow(): void
    {
        Event::fake([MagicLinkRequested::class]);

        $sendRes = $this->postJson('/api/auth/magic-link', [
            'email' => 'john@example.com',
        ]);

        $sendRes->assertStatus(200)
            ->assertJsonPath('ok', true);

        $capturedCode = null;
        Event::assertDispatched(MagicLinkRequested::class, function ($event) use (&$capturedCode) {
            $capturedCode = $event->code;
            return true;
        });

        // Authenticate via mobile numeric magic code
        $verifyRes = $this->postJson('/api/auth/magic-link/verify', [
            'email' => 'john@example.com',
            'code' => $capturedCode,
        ], [
            'X-Client-Type' => 'mobile',
        ]);

        $verifyRes->assertStatus(200)
            ->assertJsonPath('ok', true)
            ->assertJsonPath('data.user.email', 'john@example.com');

        $this->assertArrayHasKey('access_token', $verifyRes->json('data'));
    }

    public function test_account_deletion_with_full_gdpr_cleanup(): void
    {
        Event::fake([AccountDeleted::class]);

        // Link multiple resources to this user
        $this->user->createToken('device_token');

        AuthDevice::create([
            'user_id' => $this->user->id,
            'device_id' => 'device_abc_123',
            'platform' => 'ios',
            'fcm_token' => 'fcm_xyz_999',
        ]);

        AuthTwoFactor::create([
            'user_id' => $this->user->id,
            'secret' => 'JBSWY3DPEHPK3PXP',
            'confirmed_at' => now(),
        ]);

        AuthSocialAccount::create([
            'user_id' => $this->user->id,
            'provider' => 'google',
            'provider_id' => 'google_sub_123',
        ]);

        $this->actingAs($this->user);

        // Delete account requiring password confirmation
        $deleteRes = $this->deleteJson('/api/auth/account', [
            'password' => 'Secret123!@#',
        ]);

        $deleteRes->assertStatus(200)
            ->assertJsonPath('ok', true);

        Event::assertDispatched(AccountDeleted::class);

        // Verify full cascade and purge
        $this->assertDatabaseMissing('users', ['id' => $this->user->id]);
        $this->assertDatabaseMissing('auth_devices', ['user_id' => $this->user->id]);
        $this->assertDatabaseMissing('auth_two_factor', ['user_id' => $this->user->id]);
        $this->assertDatabaseMissing('auth_social_accounts', ['user_id' => $this->user->id]);
        $this->assertEquals(0, $this->user->tokens()->count());
    }

    public function test_magic_link_supports_custom_mobile_deep_linking(): void
    {
        Event::fake([MagicLinkRequested::class]);

        config()->set('omni-auth.magic_link.allowed_schemes', ['myflutterapp']);

        // 1. Untrusted evil open-redirect domain is rejected
        $evilRes = $this->postJson('/api/auth/magic-link', [
            'email' => 'john@example.com',
            'redirect_url' => 'https://evil.example.com/steal',
        ]);
        $evilRes->assertStatus(422)
            ->assertJsonValidationErrors(['redirect_url']);

        // 2. Allowed mobile deep-link scheme succeeds
        $customDeepLink = 'myflutterapp://auth/magic-login';

        $sendRes = $this->postJson('/api/auth/magic-link', [
            'email' => 'john@example.com',
            'redirect_url' => $customDeepLink,
        ]);

        $sendRes->assertStatus(200);

        Event::assertDispatched(MagicLinkRequested::class, function ($event) use ($customDeepLink) {
            $this->assertStringStartsWith($customDeepLink, $event->magicUrl);
            $this->assertStringContainsString('token=magic_', $event->magicUrl);
            return true;
        });
    }

    public function test_anti_abuse_rate_limiting_for_dispatch_requests(): void
    {
        Event::fake();

        // 5 requests are permitted within 1 minute
        for ($i = 0; $i < 5; $i++) {
            $res = $this->postJson('/api/auth/forgot-password', [
                'email' => 'throttled@example.com',
            ]);
            $res->assertStatus(200);
        }

        // 6th request triggers anti-abuse rate limit
        $blockedRes = $this->postJson('/api/auth/forgot-password', [
            'email' => 'throttled@example.com',
        ]);

        $blockedRes->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }
}
