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
            ->subject("Verify your {$appName} email address")
            ->greeting("Hello {$name},")
            ->line("Thanks for signing up for {$appName}! Please confirm your email address to complete your registration.");

        if ($this->otp) {
            $mail->line('Your verification code is:')
                ->line('# ' . $this->otp);
        }

        if ($this->signedUrl) {
            $mail->line('Or click the button below to verify directly:')
                ->action('Verify Email Address', $this->signedUrl);
        }

        return $mail
            ->line("This code and link will expire in {$ttl} minutes.")
            ->line("If you didn't create an account with {$appName}, you can safely ignore this email.")
            ->salutation("Regards,\n**{$appName} Team**");
    }
}
