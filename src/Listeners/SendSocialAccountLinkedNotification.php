<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Listeners;

use KaziOmar\OmniAuth\Events\SocialAccountLinked;
use KaziOmar\OmniAuth\Notifications\NotificationHelper;

class SendSocialAccountLinkedNotification
{
    /**
     * Handle the event.
     */
    public function handle(SocialAccountLinked $event): void
    {
        $notification = NotificationHelper::make('social_account_linked', [
            $event->provider,
        ]);

        if ($notification && isset($event->user)) {
            NotificationHelper::send($event->user, $notification);
        }
    }
}

