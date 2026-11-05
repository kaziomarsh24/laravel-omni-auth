<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Listeners;

use KaziOmar\OmniAuth\Events\SocialAccountUnlinked;
use KaziOmar\OmniAuth\Notifications\NotificationHelper;

class SendSocialAccountUnlinkedNotification
{
    /**
     * Handle the event.
     */
    public function handle(SocialAccountUnlinked $event): void
    {
        $notification = NotificationHelper::make('social_account_unlinked', [
            $event->provider,
        ]);

        if ($notification && isset($event->user)) {
            NotificationHelper::send($event->user, $notification);
        }
    }
}
