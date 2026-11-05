<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Listeners;

use KaziOmar\OmniAuth\Events\PasswordResetOtpRequested;
use KaziOmar\OmniAuth\Notifications\NotificationHelper;

class SendPasswordResetOtpNotification
{
    /**
     * Handle the event.
     */
    public function handle(PasswordResetOtpRequested $event): void
    {
        $notification = NotificationHelper::make('password_reset_otp', [
            $event->otp,
            $event->resetUrl ?? $event->signedUrl ?? null,
        ]);

        if ($notification) {
            NotificationHelper::send($event->user, $notification);
        }
    }
}
