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
        $name = NotificationHelper::sanitizeName(is_object($notifiable) ? ($notifiable->name ?? null) : null);

        return (new MailMessage())
            ->subject("Your {$appName} verification code")
            ->greeting("Hello {$name},")
            ->line("Here is your one-time verification code for {$appName}:")
            ->line('# ' . $this->otp)
            ->line('This code is valid for 10 minutes and can only be used once.')
            ->line('⚠️ **If you did not try to sign in just now**, someone may know your password. We strongly recommend changing your password right away to keep your account safe.')
            ->salutation("Regards,\n**{$appName} Security Team**");
    }
}
