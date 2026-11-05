<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Notifications;

use Illuminate\Support\Facades\Notification;

class NotificationHelper
{
    /**
     * Dispatch a notification to a user or direct email recipient.
     * Wrapped in try/catch to report transport failures safely without crashing the request or allowing user enumeration.
     */
    public static function send(mixed $recipient, mixed $notification): void
    {
        try {
            if (is_object($recipient) && method_exists($recipient, 'notify')) {
                $recipient->notify($notification);
            } elseif (is_object($recipient) && !empty($recipient->email)) {
                Notification::route('mail', $recipient->email)->notify($notification);
            } elseif (is_string($recipient) && filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
                Notification::route('mail', $recipient)->notify($notification);
            }
        } catch (\Throwable $e) {
            report($e);
        }
    }

    /**
     * Sanitize user names or strings before interpolation into Markdown mail templates.
     * Prevents Markdown link injection, heading forgery, and HTML phishing attacks.
     */
    public static function sanitizeName(mixed $name): string
    {
        if (!is_string($name) || trim($name) === '') {
            return 'there';
        }

        $clean = strip_tags($name);
        // Strip URLs from name to prevent auto-linking
        $clean = preg_replace('/https?:\/\/\S+/i', '', $clean);
        // Strip Markdown and HTML control characters
        $clean = preg_replace('/[\[\]\(\)\*\_`~<>#\\\\\|]/', '', (string) $clean);
        $clean = trim((string) preg_replace('/\s+/', ' ', (string) $clean));

        return $clean !== '' ? $clean : 'there';
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
