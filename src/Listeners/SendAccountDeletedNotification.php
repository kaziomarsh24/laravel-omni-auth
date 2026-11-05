<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Listeners;

use KaziOmar\OmniAuth\Events\AccountDeleted;
use KaziOmar\OmniAuth\Notifications\NotificationHelper;

class SendAccountDeletedNotification
{
    /**
     * Handle the event.
     */
    public function handle(AccountDeleted $event): void
    {
        $user = $event->user;
        $email = $user->email ?? (method_exists($user, 'getEmailForVerification') ? $user->getEmailForVerification() : null);
        $name = $user->name ?? null;

        if (!$email) {
            return;
        }

        $notification = NotificationHelper::make('account_deleted', [
            $email,
            $name,
        ]);

        if ($notification) {
            NotificationHelper::send($email, $notification);
        }
    }
}
