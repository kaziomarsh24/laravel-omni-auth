<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Listeners;

use KaziOmar\OmniAuth\Events\TwoFactorDisabled;
use KaziOmar\OmniAuth\Events\TwoFactorEnabled;
use KaziOmar\OmniAuth\Notifications\NotificationHelper;

class SendTwoFactorStatusNotification
{
    /**
     * Handle 2FA enabled event.
     */
    public function handleEnabled(TwoFactorEnabled $event): void
    {
        $notification = NotificationHelper::make('two_factor_status', ['enabled']);

        if ($notification && isset($event->user)) {
            NotificationHelper::send($event->user, $notification);
        }
    }

    /**
     * Handle 2FA disabled event.
     */
    public function handleDisabled(TwoFactorDisabled $event): void
    {
        $notification = NotificationHelper::make('two_factor_status', ['disabled']);

        if ($notification && isset($event->user)) {
            NotificationHelper::send($event->user, $notification);
        }
    }
}
