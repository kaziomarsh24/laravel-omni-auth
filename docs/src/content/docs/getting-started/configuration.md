---
title: Configuration & Environment Variables
description: Complete option-by-option reference for config/omni-auth.php and .env environment variables with deep cross-links to feature guides.
---

The OmniAuth configuration file is published to `config/omni-auth.php`. Every setting can be controlled via `.env` variables for zero-code deployments or customized directly in PHP for advanced behavior.

---

## Complete `.env` Reference Cheat Sheet

Every environment variable supported by Laravel OmniAuth, its default value, and deep links to the architectural guides where it takes effect:

<div class="comparison-table-wrapper">

| Environment Variable | Config Key | Default | Description | Deep Guide Link |
| :--- | :--- | :---: | :--- | :--- |
| `OMNI_DEFAULT_CLIENT` | `client_detection.default_client` | `'web'` | Fallback client mode when headers/signatures are omitted (`'web'` or `'mobile'`). | [Dual-Mode Tokens](/laravel-omni-auth/architecture/dual-mode-tokens/) |
| `OMNI_COOKIE_NAME` | `cookie.name` | `'omni_access_token'` | Name of the encrypted HttpOnly access token cookie. | [Dual-Mode Tokens](/laravel-omni-auth/architecture/dual-mode-tokens/) |
| `OMNI_REFRESH_COOKIE_NAME` | `cookie.refresh_name` | `'omni_refresh_token'` | Name of the encrypted HttpOnly refresh token cookie. | [Token Rotation](/laravel-omni-auth/architecture/token-rotation/) |
| `OMNI_COOKIE_DOMAIN` | `cookie.domain` | `null` | Cookie domain (e.g. `'.example.com'` for cross-subdomain SSO). | [Security Defenses](/laravel-omni-auth/architecture/security-defenses/) |
| `OMNI_COOKIE_SECURE` | `cookie.secure` | `null` | Forces HTTPS-only cookies (`null` auto-detects request protocol). | [Security Defenses](/laravel-omni-auth/architecture/security-defenses/) |
| `OMNI_COOKIE_SAMESITE` | `cookie.same_site` | `'lax'` | Cookie SameSite enforcement (`'lax'`, `'strict'`, or `'none'`). | [Security Defenses](/laravel-omni-auth/architecture/security-defenses/) |
| `OMNI_CSRF_PROTECTION` | `cookie.csrf_protection` | `true` | Enforces custom headers on state-changing cookie requests. | [Security Defenses](/laravel-omni-auth/architecture/security-defenses/) |
| `OMNI_ACCESS_TOKEN_TTL` | `tokens.access_token_ttl` | `15` | Access token lifespan in minutes before rotation is required. | [Token Rotation](/laravel-omni-auth/architecture/token-rotation/) |
| `OMNI_REFRESH_TOKEN_TTL` | `tokens.refresh_token_ttl` | `43200` | Refresh token sliding expiration in minutes (default 30 days). | [Token Rotation](/laravel-omni-auth/architecture/token-rotation/) |
| `OMNI_USER_MODEL` | `user_model` | `'App\\Models\\User'` | Fully-qualified Eloquent user model class. | [Customization Guide](/laravel-omni-auth/getting-started/customization/) |
| `OMNI_IDENTIFIER_COLUMN` | `identifier_column` | `'email'` | Primary login identifier column (`'email'`, `'username'`, or `'phone'`). | [Customization Guide](/laravel-omni-auth/getting-started/customization/) |
| `OMNI_USER_RESOURCE` | `user_resource` | `null` | Custom JsonResource class (defaults to built-in `OmniUserResource`). | [Customization Guide](/laravel-omni-auth/getting-started/customization/) |
| `OMNI_CACHE_STORE` | `cache_store` | `null` | Dedicated cache store for OTPs and rate-limiting (e.g. `'redis'`). | [Security Defenses](/laravel-omni-auth/architecture/security-defenses/) |
| `OMNI_RATE_LIMITING_ENABLED` | `rate_limiting.enabled` | `true` | Master switch for brute-force and credential stuffing defense. | [Security Defenses](/laravel-omni-auth/architecture/security-defenses/) |
| `OMNI_MAX_LOGIN_ATTEMPTS` | `rate_limiting.max_attempts` | `5` | Maximum failed attempts per IP before temporary lockout. | [Security Defenses](/laravel-omni-auth/architecture/security-defenses/) |
| `OMNI_LOGIN_DECAY_SECONDS` | `rate_limiting.decay_seconds` | `60` | Lockout penalty window in seconds after exceeding per-IP limit. | [Security Defenses](/laravel-omni-auth/architecture/security-defenses/) |
| `OMNI_GLOBAL_MAX_ATTEMPTS` | `rate_limiting.global_max_attempts` | `20` | Account-level threshold across all IPs to thwart botnet attacks. | [Security Defenses](/laravel-omni-auth/architecture/security-defenses/) |
| `OMNI_GLOBAL_DECAY_SECONDS` | `rate_limiting.global_decay_seconds` | `900` | Account-level lockout window in seconds (default 15 minutes). | [Security Defenses](/laravel-omni-auth/architecture/security-defenses/) |
| `OMNI_PERMISSIONS_ENABLED` | `permissions.enabled` | `true` | Enables Spatie permission integration if package is installed. | [Customization Guide](/laravel-omni-auth/getting-started/customization/) |
| `OMNI_INCLUDE_PERMISSIONS_IN_RESPONSE` | `permissions.include_in_response` | `true` | Automatically includes `roles` & `permissions` arrays in user payloads. | [Customization Guide](/laravel-omni-auth/getting-started/customization/) |
| `OMNI_REGISTRATION_AUTO_LOGIN` | `registration.auto_login` | `true` | Immediately logs in newly registered users (`false` requires email verify). | [Customization Guide](/laravel-omni-auth/getting-started/customization/) |
| `OMNI_REGISTRATION_DEFAULT_ROLE` | `registration.default_role` | `null` | Spatie role name automatically assigned to new users upon registration. | [Customization Guide](/laravel-omni-auth/getting-started/customization/) |
| `OMNI_2FA_ISSUER` | `two_factor.issuer` | `null` | App name displayed in Authenticator apps (defaults to `config('app.name')`). | [Two-Factor Authentication](/laravel-omni-auth/features/two-factor-auth/) |
| `OMNI_2FA_CHALLENGE_TTL` | `two_factor.challenge_ttl` | `5` | Lifespan in minutes of intermediate `2fa_token` before challenge expires. | [Two-Factor Authentication](/laravel-omni-auth/features/two-factor-auth/) |
| `OMNI_SOCIAL_AUTO_LINK` | `social.auto_link_by_email` | `true` | Safely links social logins with pre-hijack password invalidation. | [Social Login](/laravel-omni-auth/features/social-login/) |
| `GOOGLE_CLIENT_ID` | `social.providers.google.client_id` | `null` | Google Cloud OAuth2 Web Client ID. | [Social Login](/laravel-omni-auth/features/social-login/) |
| `GOOGLE_CLIENT_SECRET` | `social.providers.google.client_secret` | `null` | Google Cloud OAuth2 Client Secret. | [Social Login](/laravel-omni-auth/features/social-login/) |
| `GOOGLE_REDIRECT_URI` | `social.providers.google.redirect` | `'/api/auth/social/google/callback'` | Server callback route for web redirect OAuth flow. | [Social Login](/laravel-omni-auth/features/social-login/) |
| `GOOGLE_MOBILE_CLIENT_IDS` | `social.providers.google.mobile_client_ids` | `''` | Comma-separated Android & iOS Client IDs for native token exchange. | [Social Login](/laravel-omni-auth/features/social-login/) |
| `APPLE_CLIENT_ID` | `social.providers.apple.client_id` | `null` | Apple Services ID (Web) or iOS App Bundle ID. | [Social Login](/laravel-omni-auth/features/social-login/) |
| `APPLE_TEAM_ID` | `social.providers.apple.team_id` | `null` | 10-character Apple Developer Team ID. | [Social Login](/laravel-omni-auth/features/social-login/) |
| `APPLE_KEY_ID` | `social.providers.apple.key_id` | `null` | 10-character Private Key ID from Apple Developer portal. | [Social Login](/laravel-omni-auth/features/social-login/) |
| `APPLE_PRIVATE_KEY` | `social.providers.apple.private_key` | `null` | Path or raw PEM content of Apple `.p8` private key file. | [Social Login](/laravel-omni-auth/features/social-login/) |
| `OMNI_RESET_OTP_TTL` | `password_reset.otp_ttl` | `15` | Lifespan in minutes of 6-digit password reset OTP codes. | [API Reference](/laravel-omni-auth/reference/api-reference/) |
| `OMNI_RESET_TOKEN_TTL` | `password_reset.token_ttl` | `15` | Lifespan in minutes of verified reset tokens before submission. | [API Reference](/laravel-omni-auth/reference/api-reference/) |
| `OMNI_RESET_MAX_ATTEMPTS` | `password_reset.max_attempts` | `5` | Maximum incorrect OTP submissions before code invalidation. | [Security Defenses](/laravel-omni-auth/architecture/security-defenses/) |
| `OMNI_ENFORCE_PASSWORD_STRENGTH` | `password_reset.enforce_strength` | `true` | Enforces Laravel Password default uncompromised complexity rules. | [Security Defenses](/laravel-omni-auth/architecture/security-defenses/) |
| `OMNI_VERIFICATION_TTL` | `verification.ttl` | `60` | Lifespan in minutes of signed email verification URLs and OTPs. | [Email Verification](/laravel-omni-auth/features/verification-and-deletion/) |
| `OMNI_MAGIC_LINK_TTL` | `magic_link.ttl` | `15` | Lifespan in minutes of single-use passwordless login links. | [Magic Links](/laravel-omni-auth/features/magic-links/) |
| `OMNI_ROUTES_ENABLED` | `routes.enabled` | `true` | Master switch to register built-in routes (`false` activates Headless mode). | [Customization Guide](/laravel-omni-auth/getting-started/customization/) |
| `OMNI_ROUTES_PREFIX` | `routes.prefix` | `'api/auth'` | Base URL prefix for all registered authentication endpoints. | [Installation Guide](/laravel-omni-auth/getting-started/installation/) |

</div>

---

## Modular Features (Opt-In Architecture)

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

> [!TIP]
> Commenting out a feature (e.g. `Features::twoFactorAuth()`) completely suppresses its routes, database tables, and middleware execution. See [Customization Guide](/laravel-omni-auth/getting-started/customization/) for building headless custom workflows.

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
- For deep architectural insights into client detection, read the [Dual-Mode Architecture Guide](/laravel-omni-auth/architecture/dual-mode-tokens/).

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

For CSRF protection mechanics and SameSite cookie best practices, refer to [Security Defenses](/laravel-omni-auth/architecture/security-defenses/).

---

## Token Lifetimes & Rotation

Configures token expiration periods:

```php
'tokens' => [
    'access_token_ttl' => env('OMNI_ACCESS_TOKEN_TTL', 15),     // 15 minutes
    'refresh_token_ttl' => env('OMNI_REFRESH_TOKEN_TTL', 43200), // 30 days (in minutes)
],
```

For details on single-use refresh token rotation, replay attack prevention, and cascade revocation, read the [Token Rotation Guide](/laravel-omni-auth/architecture/token-rotation/).

---

## User Model, Identifier & Resources

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

When set to `null`, OmniAuth defaults to `KaziOmar\OmniAuth\Http\Resources\OmniUserResource`, which automatically includes Spatie roles and permissions when installed. For examples of overriding user resources, see [Customization Guide](/laravel-omni-auth/getting-started/customization/#overriding-the-user-resource).

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

For timing attack analysis and IP vs account decay algorithms, consult the [Security Defenses Guide](/laravel-omni-auth/architecture/security-defenses/).

---

## Registration & Auto-Login Flow

Control onboarding friction and role assignment:

```php
'registration' => [
    'auto_login' => env('OMNI_REGISTRATION_AUTO_LOGIN', true),
    'default_role' => env('OMNI_REGISTRATION_DEFAULT_ROLE', null),
    'rules' => null, // null uses dynamic schema rules based on identifier_column
],
```

- When `auto_login => true` (default), users receive authentication tokens immediately upon registration with `email_verified_at = null` (Frictionless Onboarding).
- When `auto_login => false`, tokens are withheld until the user verifies their email via OTP or signed link (Strict Gatekeeper mode).
- To define custom validation rules or custom user hydration logic, see [Custom Validation Rules](/laravel-omni-auth/getting-started/customization/#customizing-registration-rules).

---

## Two-Factor Authentication (2FA)

Configure TOTP app issuers and challenge token validity:

```php
'two_factor' => [
    'issuer' => env('OMNI_2FA_ISSUER', null), // null defaults to config('app.name')
    'challenge_ttl' => env('OMNI_2FA_CHALLENGE_TTL', 5), // minutes
],
```

For QR code generation, recovery codes, and SMS fallback workflows, explore the [Two-Factor Authentication Guide](/laravel-omni-auth/features/two-factor-auth/).

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

For RS256 JWKS verification, pre-hijacking prevention, and Flutter/React Native setup, read the [Social Login & Token Exchange Guide](/laravel-omni-auth/features/social-login/).

---

## Password Reset & Passwordless Magic Links

Configure TTLs and security thresholds:

```php
'password_reset' => [
    'otp_ttl' => env('OMNI_RESET_OTP_TTL', 15),          // minutes
    'token_ttl' => env('OMNI_RESET_TOKEN_TTL', 15),      // minutes
    'max_attempts' => env('OMNI_RESET_MAX_ATTEMPTS', 5),
    'enforce_strength' => env('OMNI_ENFORCE_PASSWORD_STRENGTH', true),
],

'magic_link' => [
    'ttl' => env('OMNI_MAGIC_LINK_TTL', 15), // minutes
],

'verification' => [
    'ttl' => env('OMNI_VERIFICATION_TTL', 60), // minutes
],
```

For full implementation examples, review the [Magic Links Guide](/laravel-omni-auth/features/magic-links/) and [Verification & Deletion Guide](/laravel-omni-auth/features/verification-and-deletion/).

---

## Built-In Routes vs Headless Mode

Control URL prefix and route registration:

```php
'routes' => [
    'enabled' => env('OMNI_ROUTES_ENABLED', true),
    'prefix' => env('OMNI_ROUTES_PREFIX', 'api/auth'),
    'middleware' => ['api'],
],
```

- When `enabled => true`, all 29 production endpoints are automatically registered at `/api/auth/*`.
- When `enabled => false`, built-in routing is completely disabled. You can build custom controllers using the `Omni` Facade (`Omni::attempt()`, `Omni::issueTokenResponse()`). See [Headless Mode](/laravel-omni-auth/getting-started/customization/#headless-mode-building-custom-routes).

