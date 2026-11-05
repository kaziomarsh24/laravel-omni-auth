<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class VerifyEmailNotification extends Notification
{
    use Queueable;

    public function __construct(
        public ?string $signedUrl = null,
        public ?string $otp = null
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
        $ttl = (int) config('omni-auth.verification.ttl', 60);

        $mail = (new MailMessage())
            ->subject("Verify Your Email Address - {$appName}")
            ->greeting("Hello {$name},")
            ->line("Thank you for registering with {$appName}! Please confirm your email address to complete your registration.");

        if ($this->otp) {
            $mail->line('Your 6-digit verification code is:')
                ->line('# ' . $this->otp)
                ->line("This verification code will expire in {$ttl} minutes.");
        }

        if ($this->signedUrl) {
            $mail->action('Verify Email Address', $this->signedUrl);
        }

        return $mail
            ->line('If you did not create an account, no further action is required.')
            ->salutation("Regards,\n**{$appName} Team**");
    }
}
