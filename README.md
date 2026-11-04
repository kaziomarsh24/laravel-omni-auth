# Laravel OmniAuth

Developer-first, multi-client authentication engine for Laravel. Seamlessly delivers `HttpOnly` SameSite cookies for Web applications (Next.js, React, Vue) and JSON `Bearer` tokens for Mobile applications (Flutter, React Native) with zero-boilerplate security.

---

## Architectural Philosophy

In modern full-stack development, backend APIs must serve both web browsers and native mobile applications simultaneously:
- **Web Browsers (Next.js, React, Vue):** Storing bearer tokens in `localStorage` exposes users to XSS token theft. Web clients require secure, `HttpOnly`, `SameSite` cookies.
- **Mobile Clients (Flutter, React Native):** Mobile applications prefer stateless `Authorization: Bearer <token>` headers stored securely in device keychains.

Laravel OmniAuth detects the incoming client type automatically and delivers the appropriate authentication mechanism without requiring separate controllers or duplicated endpoints.

---

## Features (Modular & Opt-In)

- **Dual-Mode Delivery:** Automatic `HttpOnly, Secure` cookies for Web and Bearer JSON for Mobile.
- **Token Rotation:** Single-use refresh token rotation with immediate revocation of compromised tokens.
- **Unified Middleware:** Single `omni.auth` middleware authenticates requests via cookie or bearer header.
- **Brute-Force Rate Limiting:** Built-in IP and identifier throttling with HTTP 429 backoff headers.
- **Standard Laravel Events:** Automatically dispatches `Login`, `Failed`, and `Logout` events for audit logging.
- **Reverse Proxy Ready:** Dynamic HTTPS detection supporting AWS ALB, Cloudflare, Nginx, and Docker.

---

## Requirements

- PHP 8.2, 8.3, 8.4, or 8.5
- Laravel 11, 12, or 13
- Laravel Sanctum 4.x

---

## Installation

```bash
composer require thekaziomar/laravel-omni-auth
```

Publish configuration:

```bash
php artisan vendor:publish --tag="omni-auth-config"
```

---

## Quickstart

### 1. Authenticate (Web or Mobile)

In your controller:

```php
use KaziOmar\OmniAuth\Facades\Omni;
use Illuminate\Http\Request;

public function login(Request $request)
{
    return Omni::attempt($request->only('email', 'password'));
}
```

- When requested by a browser, Omni delivers access and refresh tokens inside secure `HttpOnly` cookies.
- When requested by a mobile app (sending `X-Client-Type: mobile` or native User-Agent), Omni returns tokens in the JSON response body.

### 2. Protect Routes

```php
Route::middleware('omni.auth')->group(function () {
    Route::get('/user', function (Request $request) {
        return $request->user();
    });
});
```

### 3. Refresh Tokens

```php
public function refresh(Request $request)
{
    return Omni::refresh($request);
}
```

### 4. Logout

```php
public function logout(Request $request)
{
    return Omni::logout($request);
}
```

---

## License

The MIT License (MIT). Please see [LICENSE.md](LICENSE.md) for more information.
