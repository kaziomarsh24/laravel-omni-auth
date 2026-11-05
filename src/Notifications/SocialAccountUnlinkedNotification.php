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
        $name = NotificationHelper::sanitizeName(is_object($notifiable) ? ($notifiable->name ?? null) : null);
        $providerName = ucfirst($this->provider);
        $timestamp = now()->toRfc2822String();

        return (new MailMessage())
            ->subject("Security Alert: {$providerName} was disconnected from your account - {$appName}")
            ->greeting("Hello {$name},")
            ->line("The **{$providerName}** account connected to your {$appName} profile was disconnected.")
            ->line("**When:** {$timestamp} (UTC)")
            ->line('If you did this, no further action is needed.')
            ->line("⚠️ If you didn't authorize disconnecting this provider, please check your account settings right away.")
            ->salutation("Regards,\n**{$appName} Security Team**");
    }
}
