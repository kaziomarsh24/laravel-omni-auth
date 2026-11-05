<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class TwoFactorStatusChangedNotification extends Notification
{
    use Queueable;

    public function __construct(
        public string $status // 'enabled' or 'disabled'
    ) {}

    /**
     * Get the notification's delivery channels.
     *
     * @return array<int, string>
     */
    public function via(mixed $notifiable): array
    {
        return config('omni-auth.notifications.channels', ['mail']);
    }

    /**
     * Build the mail representation of the notification.
     */
    public function toMail(mixed $notifiable): MailMessage
    {
        $appName = (string) (config('app.name') ?: 'Laravel');
        $name = is_object($notifiable) && !empty($notifiable->name) ? (string) $notifiable->name : 'there';
        $statusLabel = strtolower($this->status) === 'enabled' ? 'Enabled' : 'Disabled';
        $timestamp = now()->toRfc2822String();

        $mail = (new MailMessage())
            ->subject("Security Alert: Two-Factor Authentication {$statusLabel} - {$appName}")
            ->greeting("Hello {$name},")
            ->line("Two-Factor Authentication (2FA) was recently **{$statusLabel}** on your {$appName} account.")
            ->line("**Status:** {$statusLabel}")
            ->line("**Time:** {$timestamp} (UTC)");

        if (strtolower($this->status) === 'disabled') {
            $mail->line('⚠️ **Warning:** Disabling 2FA significantly reduces your account security. If you did not authorize this change, please re-enable two-factor authentication immediately and change your password.');
        } else {
            $mail->line('Your account is now protected with an additional layer of security.');
        }

        return $mail->salutation("Regards,\n**{$appName} Security Team**");
    }
}
