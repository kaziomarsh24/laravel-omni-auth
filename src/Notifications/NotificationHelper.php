<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Notifications;

use Illuminate\Support\Facades\Notification;

class NotificationHelper
{
    /**
     * Dispatch a notification to a user or direct email recipient.
     */
    public static function send(mixed $recipient, mixed $notification): void
    {
        if (is_object($recipient) && method_exists($recipient, 'notify')) {
            $recipient->notify($notification);
        } elseif (is_object($recipient) && !empty($recipient->email)) {
            Notification::route('mail', $recipient->email)->notify($notification);
        } elseif (is_string($recipient) && filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
            Notification::route('mail', $recipient)->notify($notification);
        }
    }

    /**
     * Resolve a notification instance from config mapping or fallback class.
     */
    public static function make(string $key, array $args = []): ?object
    {
        $enabled = config('omni-auth.notifications.enabled', true);
        if (!$enabled) {
            return null;
        }

        $toggle = config("omni-auth.notifications.toggles.{$key}", true);
        if (!$toggle) {
            return null;
        }

        $class = config("omni-auth.notifications.classes.{$key}");
        if (!$class || !class_exists($class)) {
            return null;
        }

        return new $class(...$args);
    }
}
