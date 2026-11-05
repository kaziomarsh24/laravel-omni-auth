<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Listeners;

use KaziOmar\OmniAuth\Events\TwoFactorFallbackOtpRequested;
use KaziOmar\OmniAuth\Notifications\NotificationHelper;

class SendTwoFactorFallbackOtpNotification
{
    /**
     * Handle the event.
     */
    public function handle(TwoFactorFallbackOtpRequested $event): void
    {
        $notification = NotificationHelper::make('two_factor_fallback_otp', [
            $event->otp,
        ]);

        if ($notification) {
            NotificationHelper::send($event->user, $notification);
        }
    }
}

