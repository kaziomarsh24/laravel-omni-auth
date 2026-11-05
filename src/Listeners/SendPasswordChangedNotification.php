<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Listeners;

use Illuminate\Auth\Events\PasswordReset;
use KaziOmar\OmniAuth\Events\PasswordChanged;
use KaziOmar\OmniAuth\Notifications\NotificationHelper;

class SendPasswordChangedNotification
{
    /**
     * Handle the event.
     */
    public function handle(PasswordChanged|PasswordReset $event): void
    {
        $notification = NotificationHelper::make('password_changed');

        if ($notification && isset($event->user)) {
            NotificationHelper::send($event->user, $notification);
        }
    }
}
