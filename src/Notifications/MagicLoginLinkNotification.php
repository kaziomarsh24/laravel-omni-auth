<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class MagicLoginLinkNotification extends Notification
{
    use Queueable;

    public function __construct(
        public string $magicUrl,
        public ?string $code = null
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
        $ttl = (int) config('omni-auth.magic_link.ttl', 15);

        $mail = (new MailMessage())
            ->subject("Sign in to {$appName}")
            ->greeting("Hello {$name},");

        if ($this->code) {
            $mail->line("Use this temporary code to sign in to your {$appName} account:")
                ->line('# ' . $this->code)
                ->line('Or click below to sign in directly:');
        } else {
            $mail->line("Click below to sign in to your {$appName} account:");
        }

        return $mail
            ->action("Sign in to {$appName}", $this->magicUrl)
            ->line("This link and code will expire in {$ttl} minutes.")
            ->line("If you didn't request this email, you can safely ignore it—no one can access your account without it.")
            ->salutation("Regards,\n**{$appName} Team**");
    }
}
