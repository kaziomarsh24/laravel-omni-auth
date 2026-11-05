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
            ->subject("Your Magic Login Link - {$appName}")
            ->greeting("Hello {$name},")
            ->line("We received a request to log in to your {$appName} account without a password.")
            ->action('Sign In Instantly', $this->magicUrl);

        if ($this->code) {
            $mail->line('If you are using a mobile application or prefer using a numeric passcode, enter the 6-digit code below:')
                ->line('# ' . $this->code);
        }

        return $mail
            ->line("This login link and passcode are single-use and will expire in {$ttl} minutes.")
            ->line('If you did not request this link, you can safely ignore this email. No one can access your account without this link.')
            ->salutation("Regards,\n**{$appName} Team**");
    }
}
