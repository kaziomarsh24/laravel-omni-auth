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
        // Default client fallback when detection heuristics cannot determine ('web' or 'mobile')
        'default_client' => env('OMNI_DEFAULT_CLIENT', 'web'),

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
        'secure' => env('OMNI_COOKIE_SECURE', null), // null = auto-detect via request()->isSecure()
        'http_only' => true,
        'same_site' => env('OMNI_COOKIE_SAMESITE', 'lax'), // 'lax', 'strict', or 'none'
        // Require custom header (X-Requested-With / X-Client-Type) on state-changing requests when authenticated via cookie
        'csrf_protection' => env('OMNI_CSRF_PROTECTION', true),
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
    | User Model, Guard, & Identifier
    |--------------------------------------------------------------------------
    */
    'user_model' => env('OMNI_USER_MODEL', 'App\\Models\\User'),
    'identifier_column' => env('OMNI_IDENTIFIER_COLUMN', 'email'), // 'email', 'username', or 'phone'
    'guard' => 'sanctum',

    /*
    |--------------------------------------------------------------------------
    | Custom API Resource
    |--------------------------------------------------------------------------
    | Specify your own JsonResource class (e.g. App\Http\Resources\UserResource)
    | to fully customize how user models are returned in responses.
    | Leave null to use the built-in OmniUserResource with Spatie support.
    */
    'user_resource' => env('OMNI_USER_RESOURCE', null),

    /*
    |--------------------------------------------------------------------------
    | Cache Store
    |--------------------------------------------------------------------------
    | Cache store for OTPs, rate-limiting state, and token replay defense.
    | Set null to use Laravel's default store (redis, database, file, etc.).
    */
    'cache_store' => env('OMNI_CACHE_STORE', null),

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting (Brute-Force & Distributed Botnet Protection)
    |--------------------------------------------------------------------------
    */
    'rate_limiting' => [
        'enabled' => env('OMNI_RATE_LIMITING_ENABLED', true),
        'max_attempts' => env('OMNI_MAX_LOGIN_ATTEMPTS', 5),
        'decay_seconds' => env('OMNI_LOGIN_DECAY_SECONDS', 60),

        // Global account-level rate limit across all IPs (distributed attack defense)
        'global_max_attempts' => env('OMNI_GLOBAL_MAX_ATTEMPTS', 20),
        'global_decay_seconds' => env('OMNI_GLOBAL_DECAY_SECONDS', 900), // 15 minutes
    ],

    /*
    |--------------------------------------------------------------------------
    | Default Roles & Permissions
    |--------------------------------------------------------------------------
    */
    'default_role' => env('OMNI_DEFAULT_ROLE', null),

    /*
    |--------------------------------------------------------------------------
    | Roles & Permissions (Spatie Permission Integration)
    |--------------------------------------------------------------------------
    | If spatie/laravel-permission is used on your User model (or any HasRoles
    | trait), OmniAuth automatically includes user roles and permissions in
    | authentication responses (login, register, me) for frontend authorization.
    */
    'permissions' => [
        'enabled' => env('OMNI_PERMISSIONS_ENABLED', true),
        'include_in_response' => env('OMNI_INCLUDE_PERMISSIONS_IN_RESPONSE', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Registration Settings
    |--------------------------------------------------------------------------
    | Configure auto-login behavior and default validation rules for new user
    | registration when a FormRequest is not explicitly passed.
    */
    'registration' => [
        'auto_login' => env('OMNI_REGISTRATION_AUTO_LOGIN', true),
        'default_role' => env('OMNI_REGISTRATION_DEFAULT_ROLE', null),
        'rules' => null, // null uses dynamic schema rules based on identifier_column
    ],

    /*
    |--------------------------------------------------------------------------
    | Ready-to-Use Routes
    |--------------------------------------------------------------------------
    | Opt-in built-in authentication routes. When enabled, standard endpoints
    | (/login, /register, /refresh, /logout, /me) are automatically registered.
    */
    'routes' => [
        'enabled' => env('OMNI_ROUTES_ENABLED', true),
        'prefix' => env('OMNI_ROUTES_PREFIX', 'api/auth'),
        'middleware' => ['api'],
    ],
];
