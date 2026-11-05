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
        $name = $this->name ?? (is_object($notifiable) && !empty($notifiable->name) ? (string) $notifiable->name : 'there');

        return (new MailMessage())
            ->subject("Your {$appName} account has been closed")
            ->greeting("Hello {$name},")
            ->line("As requested, your {$appName} account and all associated personal data have been permanently deleted.")
            ->line('All active sessions and authentication tokens have been wiped from our systems.')
            ->line("We're sorry to see you go! Thank you for having been with us.")
            ->line('If this account was closed by mistake, please reach out to our support team right away.')
            ->salutation("Best regards,\n**{$appName} Team**");
    }
}
