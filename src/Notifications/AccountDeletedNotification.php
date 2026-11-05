<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class AccountDeletedNotification extends Notification
{
    use Queueable;

    public function __construct(
        public string $email,
        public ?string $name = null
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
        $name = NotificationHelper::sanitizeName($this->name ?? (is_object($notifiable) ? ($notifiable->name ?? null) : null));

        return (new MailMessage())
            ->subject("Your {$appName} account has been closed")
            ->greeting("Hello {$name},")
            ->line("As requested, your {$appName} account and all associated personal data have been permanently deleted.")
            ->line('All active sessions, credentials, and authentication tokens have been permanently wiped from our systems.')
            ->line("We're sorry to see you go! Thank you for having been part of our community, and we wish you all the best.")
            ->salutation("Best regards,\n**{$appName} Team**");
    }
}
