<?php

namespace KaziOmar\OmniAuth\Tests;

use Illuminate\Support\Facades\Notification;
use KaziOmar\OmniAuth\Events\AccountDeleted;
use KaziOmar\OmniAuth\Events\EmailVerificationRequested;
use KaziOmar\OmniAuth\Events\MagicLinkRequested;
use KaziOmar\OmniAuth\Events\PasswordChanged;
use KaziOmar\OmniAuth\Events\PasswordResetOtpRequested;
use KaziOmar\OmniAuth\Events\SocialAccountLinked;
use KaziOmar\OmniAuth\Events\SocialAccountUnlinked;
use KaziOmar\OmniAuth\Events\TwoFactorDisabled;
use KaziOmar\OmniAuth\Events\TwoFactorEnabled;
use KaziOmar\OmniAuth\Events\TwoFactorFallbackOtpRequested;
use KaziOmar\OmniAuth\Facades\Omni;
use KaziOmar\OmniAuth\Notifications\AccountDeletedNotification;
use KaziOmar\OmniAuth\Notifications\MagicLoginLinkNotification;
use KaziOmar\OmniAuth\Notifications\PasswordChangedNotification;
use KaziOmar\OmniAuth\Notifications\ResetPasswordOtpNotification;
use KaziOmar\OmniAuth\Notifications\SocialAccountLinkedNotification;
use KaziOmar\OmniAuth\Notifications\SocialAccountUnlinkedNotification;
use KaziOmar\OmniAuth\Notifications\TwoFactorFallbackOtpNotification;
use KaziOmar\OmniAuth\Notifications\TwoFactorStatusChangedNotification;
use KaziOmar\OmniAuth\Notifications\VerifyEmailNotification;

class NotificationDeliveryTest extends TestCase
{
    protected TestUser $user;

    protected function setUp(): void
    {
        parent::setUp();

        $this->user = TestUser::create([
            'name' => 'Kazi Omar',
            'email' => 'kazi@example.com',
            'password' => bcrypt('Password123!@#'),
        ]);
    }

    public function test_password_reset_otp_notification_content_and_dispatch(): void
    {
        Notification::fake();

        event(new PasswordResetOtpRequested($this->user, '582910', 'https://example.com/reset?token=abc'));

        Notification::assertSentTo($this->user, ResetPasswordOtpNotification::class, function ($notification) {
            $mail = $notification->toMail($this->user);

            $this->assertStringContainsString('Password Reset Request', $mail->subject);
            $this->assertStringContainsString('Hello Kazi Omar,', $mail->greeting);
            $this->assertContains('# 582910', $mail->introLines);
            $this->assertSame('Reset Password', $mail->actionText);
            $this->assertSame('https://example.com/reset?token=abc', $mail->actionUrl);
            return true;
        });
    }

    public function test_verify_email_notification_content_and_dispatch(): void
    {
        Notification::fake();

        event(new EmailVerificationRequested($this->user, 'https://example.com/verify-email', '123456'));

        Notification::assertSentTo($this->user, VerifyEmailNotification::class, function ($notification) {
            $mail = $notification->toMail($this->user);

            $this->assertStringContainsString('Verify Your Email Address', $mail->subject);
            $this->assertContains('# 123456', $mail->introLines);
            $this->assertSame('Verify Email Address', $mail->actionText);
            $this->assertSame('https://example.com/verify-email', $mail->actionUrl);
            return true;
        });
    }

    public function test_magic_login_link_notification_content_and_dispatch(): void
    {
        Notification::fake();

        event(new MagicLinkRequested($this->user, 'https://example.com/magic?token=xyz', '654321'));

        Notification::assertSentTo($this->user, MagicLoginLinkNotification::class, function ($notification) {
            $mail = $notification->toMail($this->user);

            $this->assertStringContainsString('Your Magic Login Link', $mail->subject);
            $this->assertSame('Sign In Instantly', $mail->actionText);
            $this->assertSame('https://example.com/magic?token=xyz', $mail->actionUrl);
            $allLines = array_merge($mail->introLines, $mail->outroLines);
            $this->assertContains('# 654321', $allLines);
            return true;
        });
    }

    public function test_two_factor_fallback_otp_notification_content_and_dispatch(): void
    {
        Notification::fake();

        event(new TwoFactorFallbackOtpRequested($this->user, '998877'));

        Notification::assertSentTo($this->user, TwoFactorFallbackOtpNotification::class, function ($notification) {
            $mail = $notification->toMail($this->user);

            $this->assertStringContainsString('Two-Factor Authentication Backup Passcode', $mail->subject);
            $this->assertContains('# 998877', $mail->introLines);
            $this->assertStringContainsString('Important Security Warning', implode(' ', $mail->introLines));
            return true;
        });
    }

    public function test_password_changed_notification_content_and_dispatch(): void
    {
        Notification::fake();

        event(new PasswordChanged($this->user));

        Notification::assertSentTo($this->user, PasswordChangedNotification::class, function ($notification) {
            $mail = $notification->toMail($this->user);

            $this->assertStringContainsString('Security Alert: Your Password Was Changed', $mail->subject);
            $this->assertStringContainsString('If you did not make this change', implode(' ', $mail->introLines));
            return true;
        });
    }

    public function test_two_factor_status_changed_notification_for_enabled_and_disabled(): void
    {
        Notification::fake();

        event(new TwoFactorEnabled($this->user));

        Notification::assertSentTo($this->user, TwoFactorStatusChangedNotification::class, function ($notification) {
            $mail = $notification->toMail($this->user);
            return str_contains($mail->subject, 'Two-Factor Authentication Enabled') && $notification->status === 'enabled';
        });

        event(new TwoFactorDisabled($this->user));

        Notification::assertSentTo($this->user, TwoFactorStatusChangedNotification::class, function ($notification) {
            $mail = $notification->toMail($this->user);
            return str_contains($mail->subject, 'Two-Factor Authentication Disabled') && $notification->status === 'disabled';
        });

        Notification::assertSentToTimes($this->user, TwoFactorStatusChangedNotification::class, 2);
    }

    public function test_social_account_linked_and_unlinked_notifications(): void
    {
        Notification::fake();

        event(new SocialAccountLinked($this->user, 'github'));

        Notification::assertSentTo($this->user, SocialAccountLinkedNotification::class, function ($notification) {
            $mail = $notification->toMail($this->user);
            $this->assertStringContainsString('Github Account Connected', $mail->subject);
            $this->assertSame('github', $notification->provider);
            return true;
        });

        event(new SocialAccountUnlinked($this->user, 'google'));

        Notification::assertSentTo($this->user, SocialAccountUnlinkedNotification::class, function ($notification) {
            $mail = $notification->toMail($this->user);
            $this->assertStringContainsString('Google Account Disconnected', $mail->subject);
            $this->assertSame('google', $notification->provider);
            return true;
        });
    }

    public function test_account_deleted_notification_content_and_dispatch(): void
    {
        Notification::fake();

        event(new AccountDeleted($this->user));

        Notification::assertSentOnDemand(AccountDeletedNotification::class, function ($notification, $channels, $notifiable) {
            $this->assertSame('kazi@example.com', $notifiable->routes['mail']);
            $mail = $notification->toMail($notifiable);
            $this->assertStringContainsString('Account Has Been Permanently Deleted', $mail->subject);
            $this->assertStringContainsString('GDPR', implode(' ', $mail->introLines));
            return true;
        });
    }

    public function test_global_notifications_disabled_toggle(): void
    {
        Notification::fake();
        config(['omni-auth.notifications.enabled' => false]);

        event(new PasswordResetOtpRequested($this->user, '111111'));
        event(new PasswordChanged($this->user));
        event(new TwoFactorEnabled($this->user));

        Notification::assertNothingSent();
    }

    public function test_individual_notification_toggle(): void
    {
        Notification::fake();
        config(['omni-auth.notifications.toggles.password_reset_otp' => false]);

        // password_reset_otp is toggled off -> should NOT send
        event(new PasswordResetOtpRequested($this->user, '111111'));
        Notification::assertNotSentTo($this->user, ResetPasswordOtpNotification::class);

        // password_changed is still toggled on -> SHOULD send
        event(new PasswordChanged($this->user));
        Notification::assertSentTo($this->user, PasswordChangedNotification::class);
    }

    public function test_custom_notification_class_override(): void
    {
        Notification::fake();
        config(['omni-auth.notifications.classes.password_reset_otp' => CustomTestNotification::class]);

        event(new PasswordResetOtpRequested($this->user, '222333'));

        Notification::assertSentTo($this->user, CustomTestNotification::class);
    }

    public function test_end_to_end_forgot_password_sends_notification(): void
    {
        Notification::fake();

        $response = $this->postJson('/api/auth/forgot-password', [
            'email' => 'kazi@example.com',
        ]);

        $response->assertStatus(200);
        Notification::assertSentTo($this->user, ResetPasswordOtpNotification::class);
    }

    public function test_end_to_end_change_password_sends_notification(): void
    {
        Notification::fake();

        $response = $this->actingAs($this->user)->postJson('/api/auth/password/change', [
            'current_password' => 'Password123!@#',
            'password' => 'NewSecret456!@#',
            'password_confirmation' => 'NewSecret456!@#',
        ]);

        $response->assertStatus(200);
        Notification::assertSentTo($this->user, PasswordChangedNotification::class);
    }

    public function test_end_to_end_2fa_confirm_and_disable_sends_notifications(): void
    {
        Notification::fake();

        // 1. Setup 2FA
        $setupRes = $this->actingAs($this->user)->postJson('/api/auth/2fa/setup', [
            'password' => 'Password123!@#',
        ]);
        $setupRes->assertStatus(200);
        $secret = $setupRes->json('data.secret');
        $validCode = Omni::twoFactor()->calculateCode($secret);

        // 2. Confirm 2FA -> should send TwoFactorStatusChangedNotification (enabled)
        $confirmRes = $this->actingAs($this->user)->postJson('/api/auth/2fa/confirm', [
            'code' => $validCode,
        ]);
        $confirmRes->assertStatus(200);

        Notification::assertSentTo($this->user, TwoFactorStatusChangedNotification::class, function ($n) {
            return $n->status === 'enabled';
        });

        // 3. Disable 2FA -> should send TwoFactorStatusChangedNotification (disabled)
        $disableRes = $this->actingAs($this->user)->postJson('/api/auth/2fa/disable', [
            'password' => 'Password123!@#',
        ]);
        $disableRes->assertStatus(200);

        Notification::assertSentTo($this->user, TwoFactorStatusChangedNotification::class, function ($n) {
            return $n->status === 'disabled';
        });
    }
}

class CustomTestNotification extends \Illuminate\Notifications\Notification
{
    public function __construct(public string $otp, public ?string $signedUrl = null) {}

    public function via(mixed $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(mixed $notifiable): \Illuminate\Notifications\Messages\MailMessage
    {
        return (new \Illuminate\Notifications\Messages\MailMessage())->line('Custom notification: ' . $this->otp);
    }
}
