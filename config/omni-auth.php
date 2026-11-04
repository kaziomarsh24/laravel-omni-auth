<?php

use KaziOmar\OmniAuth\Features;

return [
    /*
    |--------------------------------------------------------------------------
    | Active Features (Opt-In Architecture)
    |--------------------------------------------------------------------------
    | Enable or disable modular authentication capabilities.
    | Comment out any feature you do not need in small projects to prevent
    | unneeded routes, migrations, and overhead from loading.
    */
    'features' => [
        Features::emailAuthentication(),
        Features::dualModeTokens(),
        Features::tokenRotation(),
        Features::registration(),
        Features::passwordReset(),

        // Features::socialLogin(),
        // Features::twoFactorAuth(),
        // Features::deviceTracking(),
        // Features::fcmTokenManagement(),
        // Features::magicLoginLink(),
        // Features::suspiciousLoginAlert(),
    ],

    /*
    |--------------------------------------------------------------------------
    | Client Detection
    |--------------------------------------------------------------------------
    | Headers and heuristics used to automatically detect whether an incoming
    | request is from a Mobile Client (Flutter/React Native) or Web Browser.
    */
    'client_detection' => [
        // Request header explicitly declaring client type: 'mobile' or 'web'
        'header_name' => 'X-Client-Type',

        // Value that identifies a mobile client
        'mobile_value' => 'mobile',

        // Auto-inspect User-Agent for mobile signatures when header is omitted
        'inspect_user_agent' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Web Cookie Delivery Settings
    |--------------------------------------------------------------------------
    | For browser requests (Next.js, React, Vue, SPA), access tokens are delivered
    | in HttpOnly, SameSite cookies to protect against XSS token theft.
    */
    'cookie' => [
        'name' => env('OMNI_COOKIE_NAME', 'omni_access_token'),
        'refresh_name' => env('OMNI_REFRESH_COOKIE_NAME', 'omni_refresh_token'),
        'domain' => env('OMNI_COOKIE_DOMAIN', null),
        'path' => '/',
        'secure' => env('OMNI_COOKIE_SECURE', null), // null = auto-detect HTTPS
        'http_only' => true,
        'same_site' => env('OMNI_COOKIE_SAMESITE', 'lax'), // 'lax', 'strict', or 'none'
    ],

    /*
    |--------------------------------------------------------------------------
    | Token Expiration Lifetimes (Minutes)
    |--------------------------------------------------------------------------
    */
    'tokens' => [
        'access_token_ttl' => env('OMNI_ACCESS_TOKEN_TTL', 15), // 15 minutes
        'refresh_token_ttl' => env('OMNI_REFRESH_TOKEN_TTL', 43200), // 30 days
    ],

    /*
    |--------------------------------------------------------------------------
    | User Model & Guard
    |--------------------------------------------------------------------------
    */
    'user_model' => env('OMNI_USER_MODEL', 'App\\Models\\User'),
    'guard' => 'sanctum',

    /*
    |--------------------------------------------------------------------------
    | Default Roles & Permissions
    |--------------------------------------------------------------------------
    | Auto-assign a default role upon registration if Spatie Permissions is present.
    */
    'default_role' => env('OMNI_DEFAULT_ROLE', 'user'),
];
