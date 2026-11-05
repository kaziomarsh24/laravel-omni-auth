<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Listeners;

use KaziOmar\OmniAuth\Events\MagicLinkRequested;
use KaziOmar\OmniAuth\Notifications\NotificationHelper;

class SendMagicLinkNotification
{
    /**
     * Handle the event.
     */
    public function handle(MagicLinkRequested $event): void
    {
        $notification = NotificationHelper::make('magic_login_link', [
            $event->magicUrl,
            $event->code,
        ]);

        if ($notification) {
            NotificationHelper::send($event->user, $notification);
        }
    }
}

