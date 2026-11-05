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

        // When true, requests with Authorization: Bearer headers are treated as mobile/API clients
        'treat_bearer_as_mobile' => env('OMNI_TREAT_BEARER_AS_MOBILE', true),

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
        'replay_detection_ttl' => env('OMNI_REPLAY_DETECTION_TTL', 15), // 15 minutes replay detection window
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
    | Two-Factor Authentication Settings
    |--------------------------------------------------------------------------
    */
    'two_factor' => [
        'issuer' => env('OMNI_2FA_ISSUER', null), // null defaults to config('app.name')
        'challenge_ttl' => env('OMNI_2FA_CHALLENGE_TTL', 5), // minutes
        'reauth_passwordless' => env('OMNI_2FA_REAUTH_PASSWORDLESS', false), // enforce email OTP re-auth for passwordless accounts
    ],

    /*
    |--------------------------------------------------------------------------
    | Social Authentication Settings (OAuth2 & Mobile Native Token Exchange)
    |--------------------------------------------------------------------------
    | Supports web redirect flow (via Socialite if installed or native OAuth)
    | and mobile native token exchange (Google ID token, Apple JWT exchange).
    */
    'social' => [
        'auto_link_by_email' => env('OMNI_SOCIAL_AUTO_LINK', true),
        'providers' => [
            'google' => [
                'client_id' => env('GOOGLE_CLIENT_ID'),
                'client_secret' => env('GOOGLE_CLIENT_SECRET'),
                'redirect' => env('GOOGLE_REDIRECT_URI', '/api/auth/social/google/callback'),
                'mobile_client_ids' => array_filter(explode(',', env('GOOGLE_MOBILE_CLIENT_IDS', ''))),
            ],
            'apple' => [
                'client_id' => env('APPLE_CLIENT_ID'), // Services ID (Web) or App Bundle ID (iOS)
                'team_id' => env('APPLE_TEAM_ID'),
                'key_id' => env('APPLE_KEY_ID'),
                'private_key' => env('APPLE_PRIVATE_KEY'),
                'redirect' => env('APPLE_REDIRECT_URI', '/api/auth/social/apple/callback'),
            ],
            'github' => [
                'client_id' => env('GITHUB_CLIENT_ID'),
                'client_secret' => env('GITHUB_CLIENT_SECRET'),
                'redirect' => env('GITHUB_REDIRECT_URI', '/api/auth/social/github/callback'),
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Password Reset & Security Settings
    |--------------------------------------------------------------------------
    */
    'password_reset' => [
        'otp_ttl' => env('OMNI_RESET_OTP_TTL', 15), // minutes
        'token_ttl' => env('OMNI_RESET_TOKEN_TTL', 15), // minutes
        'max_attempts' => env('OMNI_RESET_MAX_ATTEMPTS', 5),
        'enforce_strength' => env('OMNI_ENFORCE_PASSWORD_STRENGTH', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Email Verification Settings
    |--------------------------------------------------------------------------
    */
    'verification' => [
        'ttl' => env('OMNI_VERIFICATION_TTL', 60), // minutes
    ],

    /*
    |--------------------------------------------------------------------------
    | Passwordless Magic Link Settings
    |--------------------------------------------------------------------------
    */
    'magic_link' => [
        'ttl' => env('OMNI_MAGIC_LINK_TTL', 15), // minutes
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

    /*
    |--------------------------------------------------------------------------
    | Notification & Alert Delivery
    |--------------------------------------------------------------------------
    | OmniAuth includes batteries-included, beautifully formatted Markdown email
    | notifications out of the box for all authentication milestones and security alerts.
    |
    | When enabled, default listeners automatically dispatch notifications.
    | Set 'enabled' to false if you prefer handling delivery exclusively via
    | your own custom event listeners (e.g. SMS, WhatsApp, custom mailers).
    */
    'notifications' => [
        'enabled' => env('OMNI_NOTIFICATIONS_ENABLED', true),
        'channels' => ['mail'],

        // Customizable Notification classes (override any class with your own)
        'classes' => [
            'password_reset_otp' => \KaziOmar\OmniAuth\Notifications\ResetPasswordOtpNotification::class,
            'verify_email' => \KaziOmar\OmniAuth\Notifications\VerifyEmailNotification::class,
            'magic_login_link' => \KaziOmar\OmniAuth\Notifications\MagicLoginLinkNotification::class,
            'two_factor_fallback_otp' => \KaziOmar\OmniAuth\Notifications\TwoFactorFallbackOtpNotification::class,
            'password_changed' => \KaziOmar\OmniAuth\Notifications\PasswordChangedNotification::class,
            'two_factor_status' => \KaziOmar\OmniAuth\Notifications\TwoFactorStatusChangedNotification::class,
            'social_account_linked' => \KaziOmar\OmniAuth\Notifications\SocialAccountLinkedNotification::class,
            'social_account_unlinked' => \KaziOmar\OmniAuth\Notifications\SocialAccountUnlinkedNotification::class,
            'account_deleted' => \KaziOmar\OmniAuth\Notifications\AccountDeletedNotification::class,
        ],

        // Toggle individual notifications if needed
        'toggles' => [
            'password_reset_otp' => true,
            'verify_email' => true,
            'magic_login_link' => true,
            'two_factor_fallback_otp' => true,
            'password_changed' => true,
            'two_factor_status' => true,
            'social_account_linked' => true,
            'social_account_unlinked' => true,
            'account_deleted' => true,
        ],
    ],
];
