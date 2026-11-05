<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class ResetPasswordOtpNotification extends Notification
{
    use Queueable;

    public function __construct(
        public string $otp,
        public ?string $signedUrl = null
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
        $ttl = (int) config('omni-auth.password_reset.otp_ttl', 15);

        $mail = (new MailMessage())
            ->subject("Reset your {$appName} password")
            ->greeting("Hello {$name},")
            ->line('We received a request to reset your password. Use the verification code below to set a new password:')
            ->line('# ' . $this->otp);

        if ($this->signedUrl) {
            $mail->line('Or click the button below to reset it directly:')
                ->action('Reset Password', $this->signedUrl);
        }

        return $mail
            ->line("This code will expire in {$ttl} minutes.")
            ->line("If you didn't request a password reset, you can safely ignore this email—your account remains secure.")
            ->salutation("Regards,\n**{$appName} Team**");
    }
}
