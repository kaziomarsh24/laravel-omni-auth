<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class PasswordChangedNotification extends Notification
{
    use Queueable;

    public function __construct(
        public ?string $timestamp = null
    ) {
        $this->timestamp = $timestamp ?? now()->toRfc2822String();
    }

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

        return (new MailMessage())
            ->subject("Security Alert: Your password was changed - {$appName}")
            ->greeting("Hello {$name},")
            ->line("The password for your {$appName} account was recently changed.")
            ->line("**When:** {$this->timestamp} (UTC)")
            ->line('If you made this change, you can safely disregard this email.')
            ->line("⚠️ **If you didn't make this change**, please reset your password immediately or contact our support team to secure your account.")
            ->salutation("Regards,\n**{$appName} Security Team**");
    }
}
