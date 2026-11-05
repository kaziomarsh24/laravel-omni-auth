<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class TwoFactorFallbackOtpNotification extends Notification
{
    use Queueable;

    public function __construct(
        public string $otp
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

        return (new MailMessage())
            ->subject("[URGENT] Two-Factor Authentication Backup Passcode - {$appName}")
            ->greeting("Hello {$name},")
            ->line("A one-time emergency backup passcode was requested for Two-Factor Authentication on your {$appName} account.")
            ->line('Your single-use 2FA fallback code is:')
            ->line('# ' . $this->otp)
            ->line('This passcode is valid for 10 minutes and can only be used once.')
            ->line('⚠️ **Important Security Warning:** If you did not initiate this login attempt, someone may know your primary password. Please change your password immediately once you regain access.')
            ->salutation("Regards,\n**{$appName} Security Team**");
    }
}
