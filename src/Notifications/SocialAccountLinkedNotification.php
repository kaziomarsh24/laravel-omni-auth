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
        $name = NotificationHelper::sanitizeName(is_object($notifiable) ? ($notifiable->name ?? null) : null);
        $providerName = ucfirst($this->provider);
        $timestamp = now()->toRfc2822String();

        return (new MailMessage())
            ->subject("Security Alert: {$providerName} was connected to your account - {$appName}")
            ->greeting("Hello {$name},")
            ->line("A **{$providerName}** account was just connected to your {$appName} profile.")
            ->line("**Provider:** {$providerName}")
            ->line("**When:** {$timestamp} (UTC)")
            ->line('You can now use this provider to sign in directly.')
            ->line("If you didn't connect this account, please sign in and disconnect it immediately from your account settings.")
            ->salutation("Regards,\n**{$appName} Security Team**");
    }
}
