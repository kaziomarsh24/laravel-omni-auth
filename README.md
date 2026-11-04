# Laravel OmniAuth

[![Latest Version on Packagist](https://img.shields.io/packagist/v/thekaziomar/laravel-omni-auth.svg?style=flat-square)](https://packagist.org/packages/thekaziomar/laravel-omni-auth)
[![GitHub Tests Action Status](https://github.com/kaziomarsh24/laravel-omni-auth/actions/workflows/run-tests.yml/badge.svg)](https://github.com/kaziomarsh24/laravel-omni-auth/actions)
[![Total Downloads](https://img.shields.io/packagist/dt/thekaziomar/laravel-omni-auth.svg?style=flat-square)](https://packagist.org/packages/thekaziomar/laravel-omni-auth)
[![License](https://img.shields.io/packagist/l/thekaziomar/laravel-omni-auth.svg?style=flat-square)](LICENSE.md)

Production-grade, battle-tested authentication package for Laravel web and mobile applications.

Delivers hardened `SameSite` `HttpOnly` cookies for Web SPAs (Next.js, Nuxt, React, Vue) and short-lived `Bearer` tokens with sliding refresh tokens for native mobile applications (Flutter, React Native, iOS, Android) from a unified, zero-boilerplate API.

---

## Why OmniAuth?

Rolling authentication in Laravel usually starts with Sanctum or Breeze, but production environments serving both web browsers and mobile apps require handling complex attack surfaces:

- **Dual-Mode Delivery**: Transparently negotiates between HttpOnly cookies with CSRF validation for browsers, and Authorization headers with device keychains for mobile.
- **Refresh Token Isolation**: Prevents long-lived refresh tokens from accessing standard API routes via framework guard hooks (`Sanctum::authenticateAccessTokensUsing`).
- **Apple & Google RS256 Validation**: Strictly enforces RS256 JWKS asymmetric signatures on Apple and Google identity tokens, preventing key confusion (`HS256`) and caching failures during outages.
- **Account Pre-Hijacking Prevention**: Links verified social logins safely; unverified pre-existing passwords are automatically invalidated and prior sessions revoked.
- **Constant-Time Timing Attack Defense**: Executes pre-computed dummy bcrypt comparisons on non-existent users, keeping timing identical (~235ms vs ~259ms).
- **29 Production Endpoints**: Turnkey API surface covering credentials, TOTP 2FA, social login, device auditing, magic links, and GDPR account deletion.
- **Battle-Tested**: 90 automated tests (502 assertions) verified against two rounds of whitebox penetration auditing.

---

## Documentation

Full documentation, interactive multi-client integration guides, and API specifications are available in the documentation portal:

- **[Documentation Portal](./docs)**
  - [Overview](./docs/src/content/docs/getting-started/overview.md)
  - [Why OmniAuth?](./docs/src/content/docs/getting-started/why-omniauth.md)
  - [Installation & Setup](./docs/src/content/docs/getting-started/installation.md)
  - [Configuration Guide](./docs/src/content/docs/getting-started/configuration.md)
  - [Dual-Mode Architecture](./docs/src/content/docs/architecture/dual-mode-tokens.md)
  - [Security Defenses](./docs/src/content/docs/architecture/security-defenses.md)
  - [Two-Factor Authentication](./docs/src/content/docs/features/two-factor-auth.md)
  - [Social Login & Token Exchange](./docs/src/content/docs/features/social-login.md)
  - [Device Management](./docs/src/content/docs/features/device-management.md)
  - [Next.js Client Guide](./docs/src/content/docs/clients/nextjs-web.md)
  - [Flutter Client Guide](./docs/src/content/docs/clients/flutter-mobile.md)
  - [Complete API Reference (29 Endpoints)](./docs/src/content/docs/reference/api-reference.md)

---

## Requirements

- **PHP**: 8.2, 8.3, or 8.4
- **Laravel**: 11.x or 12.x
- **Laravel Sanctum**: 4.x

---

## Quickstart

### 1. Install via Composer

```bash
composer require thekaziomar/laravel-omni-auth
```

### 2. Run the Installer

Publishes configuration and database migrations:

```bash
php artisan omni:install
```

### 3. Prepare the User Model

Add the `HasApiTokens` and `HasOmniAuth` traits to your `App\Models\User`:

```php
namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use KaziOmar\OmniAuth\Traits\HasOmniAuth;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, HasOmniAuth;
}
```

### 4. Schedule Automated Token Pruning

In `routes/console.php`:

```php
use Illuminate\Support\Facades\Schedule;

Schedule::command('omni:prune-tokens --days=30')->daily();
```

---

## API Surface Summary

OmniAuth registers 29 production-ready endpoints under `/api/auth`:

| Module | Endpoints |
| :--- | :--- |
| **Core Auth** | `POST /login`, `POST /register`, `POST /refresh`, `POST /logout`, `GET /me` |
| **Device Sessions** | `GET /devices`, `DELETE /devices/{id}`, `POST /devices/logout-others`, `POST /devices/fcm` |
| **2FA (TOTP)** | `POST /2fa/challenge`, `POST /2fa/fallback-otp`, `POST /2fa/setup`, `POST /2fa/confirm`, `POST /2fa/recovery-codes`, `POST /2fa/disable` |
| **Social Login** | `POST /social/exchange`, `GET /social/{p}/redirect`, `GET\|POST /social/{p}/callback`, `GET /social/accounts`, `DELETE /social/{p}` |
| **Password Reset** | `POST /forgot-password`, `POST /verify-reset-otp`, `POST /reset-password` |
| **Magic Links** | `POST /magic-link`, `GET\|POST /magic-link/verify` |
| **Lifecycle** | `GET\|POST /email/verify/{id}/{hash}`, `POST /email/verify`, `POST /email/resend`, `DELETE /account` |

---

## Testing

Run the test suite with PHPUnit:

```bash
composer test
```

```text
Tests:    90 passed (502 assertions)
Duration: ~1.9s
```

---

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
