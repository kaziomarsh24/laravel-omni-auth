<?php

namespace KaziOmar\OmniAuth;

class Features
{
    public static function emailAuthentication(): string
    {
        return 'email-authentication';
    }

    public static function dualModeTokens(): string
    {
        return 'dual-mode-tokens';
    }

    public static function tokenRotation(): string
    {
        return 'token-rotation';
    }

    public static function passwordReset(): string
    {
        return 'password-reset';
    }

    public static function registration(): string
    {
        return 'registration';
    }

    public static function socialLogin(): string
    {
        return 'social-login';
    }

    public static function twoFactorAuth(): string
    {
        return 'two-factor-auth';
    }

    public static function deviceTracking(): string
    {
        return 'device-tracking';
    }

    public static function fcmTokenManagement(): string
    {
        return 'fcm-token-management';
    }

    public static function magicLoginLink(): string
    {
        return 'magic-login-link';
    }

    public static function suspiciousLoginAlert(): string
    {
        return 'suspicious-login-alert';
    }

    public static function enabled(string $feature): bool
    {
        $features = config('omni-auth.features', []);

        return in_array($feature, $features, true);
    }
}
