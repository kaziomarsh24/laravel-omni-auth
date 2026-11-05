<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class SocialAccountUnlinkedNotification extends Notification
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
            ->subject("Security Alert: {$providerName} Account Disconnected - {$appName}")
            ->greeting("Hello {$name},")
            ->line("The **{$providerName}** social account previously connected to your {$appName} profile was disconnected.")
            ->line("**Disconnected Provider:** {$providerName}")
            ->line("**Time:** {$timestamp} (UTC)")
            ->line('If you initiated this change, no further action is required.')
            ->line('⚠️ If you did not authorize disconnecting this provider, please check your account settings immediately.')
            ->salutation("Regards,\n**{$appName} Security Team**");
    }
}
