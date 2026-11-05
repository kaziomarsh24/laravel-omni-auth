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
        $name = NotificationHelper::sanitizeName(is_object($notifiable) ? ($notifiable->name ?? null) : null);
        $statusWord = strtolower($this->status) === 'enabled' ? 'turned on' : 'turned off';
        $timestamp = now()->toRfc2822String();

        $mail = (new MailMessage())
            ->subject("Security Alert: Two-step verification was {$statusWord} - {$appName}")
            ->greeting("Hello {$name},")
            ->line("Two-step verification (2FA) was recently **{$statusWord}** on your {$appName} account.")
            ->line("**When:** {$timestamp} (UTC)");

        if (strtolower($this->status) === 'disabled') {
            $mail->line("⚠️ **Warning:** With two-step verification turned off, your account is less protected. If you didn't make this change, please turn it back on and change your password right away.");
        } else {
            $mail->line('Your account is now protected with an extra layer of security.');
        }

        return $mail->salutation("Regards,\n**{$appName} Security Team**");
    }
}
