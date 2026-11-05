<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Listeners;

use KaziOmar\OmniAuth\Events\EmailVerificationRequested;
use KaziOmar\OmniAuth\Notifications\NotificationHelper;

class SendVerifyEmailNotification
{
    /**
     * Handle the event.
     */
    public function handle(EmailVerificationRequested $event): void
    {
        $notification = NotificationHelper::make('verify_email', [
            $event->verificationUrl ?? $event->signedUrl ?? null,
            $event->otp,
        ]);

        if ($notification) {
            NotificationHelper::send($event->user, $notification);
        }
    }
}
