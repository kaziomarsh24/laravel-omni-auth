<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class SocialAccountLinkedNotification extends Notification
{
    use Queueable;

    public function __construct(
        public string $provider
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
        $providerName = ucfirst($this->provider);
        $timestamp = now()->toRfc2822String();

        return (new MailMessage())
            ->subject("Security Alert: New {$providerName} Account Connected - {$appName}")
            ->greeting("Hello {$name},")
            ->line("A new **{$providerName}** social account was connected to your {$appName} profile.")
            ->line("**Connected Provider:** {$providerName}")
            ->line("**Time:** {$timestamp} (UTC)")
            ->line('You can now use this provider to sign in quickly and securely.')
            ->line('If you did not authorize this connection, please log into your account settings and unlink it immediately.')
            ->salutation("Regards,\n**{$appName} Security Team**");
    }
}
