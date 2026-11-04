---
title: Configuration
description: Complete reference for config/omni-auth.php options and environment variables.
---

The OmniAuth configuration file is published to `config/omni-auth.php`. Every setting can be controlled via `.env` variables or customized directly in PHP.

---

## Modular Features

OmniAuth uses an opt-in architecture. Enable or disable capabilities in the `features` array to keep your application minimal:

```php
use KaziOmar\OmniAuth\Features;

'features' => [
    Features::emailAuthentication(),
    Features::dualModeTokens(),
    Features::tokenRotation(),
    Features::registration(),
    Features::passwordReset(),

    // Opt-in features
    Features::socialLogin(),
    Features::twoFactorAuth(),
    Features::deviceTracking(),
    Features::fcmTokenManagement(),
    Features::magicLoginLink(),
    // Features::suspiciousLoginAlert(),
],
```

---

## Client Detection Heuristics

OmniAuth inspects incoming requests to automatically distinguish between web browsers and mobile applications (iOS/Android):

```php
'client_detection' => [
    'default_client' => env('OMNI_DEFAULT_CLIENT', 'web'),
    'header_name' => 'X-Client-Type',
    'mobile_value' => 'mobile',
    'inspect_user_agent' => true,
],
```

- When `X-Client-Type: mobile` is provided, responses deliver tokens directly in the JSON body (`access_token`, `refresh_token`).
- When `X-Client-Type` is omitted, OmniAuth inspects the `User-Agent` header for mobile runtime signatures (e.g., Dart, Flutter, Dalvik, CFNetwork). If no mobile signatures exist, it defaults to `web`, setting secure HttpOnly cookies.

---

## Web Cookie Delivery

For browser-based SPAs (Next.js, Nuxt, Vue, React), tokens are delivered via encrypted, HttpOnly cookies:

```php
'cookie' => [
    'name' => env('OMNI_COOKIE_NAME', 'omni_access_token'),
    'refresh_name' => env('OMNI_REFRESH_COOKIE_NAME', 'omni_refresh_token'),
    'domain' => env('OMNI_COOKIE_DOMAIN', null),
    'path' => '/',
    'secure' => env('OMNI_COOKIE_SECURE', null), // null auto-detects request()->isSecure()
    'http_only' => true,
    'same_site' => env('OMNI_COOKIE_SAMESITE', 'lax'),
    'csrf_protection' => env('OMNI_CSRF_PROTECTION', true),
],
```

---

## Token Lifetimes

Configures token expiration periods:

```php
'tokens' => [
    'access_token_ttl' => env('OMNI_ACCESS_TOKEN_TTL', 15),     // 15 minutes
    'refresh_token_ttl' => env('OMNI_REFRESH_TOKEN_TTL', 43200), // 30 days (in minutes)
],
```

---

## User Model & Identification Column

Configure which Eloquent model and unique column represent users:

```php
'user_model' => env('OMNI_USER_MODEL', 'App\\Models\\User'),
'identifier_column' => env('OMNI_IDENTIFIER_COLUMN', 'email'), // 'email', 'username', or 'phone'
'guard' => 'sanctum',
```

### Custom User Resource

To customize the JSON output for authenticated user endpoints (`/api/auth/me`, `/api/auth/login`, `/api/auth/register`), set `user_resource`:

```php
'user_resource' => App\Http\Resources\UserResource::class,
```

When set to `null`, OmniAuth defaults to `KaziOmar\OmniAuth\Http\Resources\OmniUserResource`, which automatically includes Spatie roles and permissions when installed.

---

## Rate Limiting & Distributed Protection

OmniAuth includes dual-layer rate limiting: per-IP limits and global account-level limits to thwart distributed credential stuffing:

```php
'rate_limiting' => [
    'enabled' => env('OMNI_RATE_LIMITING_ENABLED', true),
    'max_attempts' => env('OMNI_MAX_LOGIN_ATTEMPTS', 5),
    'decay_seconds' => env('OMNI_LOGIN_DECAY_SECONDS', 60),

    // Account-level limit across all IP addresses
    'global_max_attempts' => env('OMNI_GLOBAL_MAX_ATTEMPTS', 20),
    'global_decay_seconds' => env('OMNI_GLOBAL_DECAY_SECONDS', 900), // 15 minutes
],
```

---

## Social Login Providers

Configure credentials for OAuth 2.0 and mobile ID token verification:

```php
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
            'client_id' => env('APPLE_CLIENT_ID'), // Services ID (Web) or Bundle ID (iOS)
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
```

---

## Built-In Routes

Control URL prefix and route registration:

```php
'routes' => [
    'enabled' => env('OMNI_ROUTES_ENABLED', true),
    'prefix' => env('OMNI_ROUTES_PREFIX', 'api/auth'),
    'middleware' => ['api'],
],
```
