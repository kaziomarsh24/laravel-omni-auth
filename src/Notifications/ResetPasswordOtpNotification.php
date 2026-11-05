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
        $name = is_object($notifiable) && !empty($notifiable->name) ? (string) $notifiable->name : 'there';
        $ttl = (int) config('omni-auth.password_reset.otp_ttl', 15);

        $mail = (new MailMessage())
            ->subject("Password Reset Request - {$appName}")
            ->greeting("Hello {$name},")
            ->line('You are receiving this email because a password reset request was initiated for your account.')
            ->line('Your 6-digit one-time password (OTP) is:')
            ->line('# ' . $this->otp)
            ->line("This one-time passcode will expire in {$ttl} minutes.");

        if ($this->signedUrl) {
            $mail->line('Alternatively, you can reset your password directly by clicking the button below:')
                ->action('Reset Password', $this->signedUrl);
        }

        return $mail
            ->line('If you did not request a password reset, no further action is required. Your account password remains unchanged.')
            ->salutation("Regards,\n**{$appName} Team**");
    }
}
