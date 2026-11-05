---
title: Customization & Extending
description: Master headless mode, custom controllers with Omni facade, custom validation rules, event listeners, and the HasOmniAuth model trait.
---

Laravel OmniAuth is built on a **headless-first architecture**. While it ships with ready-to-use routes and controllers for rapid prototyping, every component can be customized, extended, or replaced with your own custom application logic.

---

## The `HasOmniAuth` Model Trait

To give your `User` model instant access to both Sanctum's token engine and OmniAuth's relational features, import `KaziOmar\OmniAuth\Traits\HasOmniAuth`.

```php
// app/Models/User.php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use KaziOmar\OmniAuth\Traits\HasOmniAuth;

class User extends Authenticatable
{
    use HasOmniAuth, Notifiable;

    protected $fillable = [
        'name',
        'email',
        'password',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];
}
```

### Out-of-the-Box Relations & Helpers

By applying `HasOmniAuth`, you immediately unlock:

```php
// 1. Sanctum Token Engine (inherited automatically)
$token = $user->createToken('api-token', ['read', 'write']);
$user->tokens();
$user->currentAccessToken();

// 2. Active & Historical Device Sessions
$devices = $user->devices; // Collection<AuthDevice>

// 3. Two-Factor Authentication Record & Quick Helper
$twoFactor = $user->twoFactor; // AuthTwoFactor model or null
if ($user->hasTwoFactorEnabled()) {
    // User has confirmed TOTP authenticator app
}

// 4. Linked Social Accounts
$providers = $user->socialAccounts; // Collection<AuthSocialAccount> (google, apple, github)
```

---

## Headless Mode (Custom Controllers)

If your enterprise project demands custom authentication routes, multi-tenant checks, or proprietary business logic (such as checking whether an account has been suspended), you can disable the built-in routes and drive the authentication pipeline directly via the `Omni` Facade.

### 1. Disable Default Routes

Set `routes.enabled` to `false` in `config/omni-auth.php`:

```php
// config/omni-auth.php

'routes' => [
    'enabled' => false, // Disables all 30 built-in /api/auth routes
    'prefix' => 'api/v1/auth',
    'middleware' => ['api'],
],
```

### 2. Define Your Own Routes

```php
// routes/api.php

use App\Http\Controllers\Auth\CustomLoginController;
use Illuminate\Support\Facades\Route;

Route::post('/v1/login', [CustomLoginController::class, 'login']);
Route::post('/v1/logout', [CustomLoginController::class, 'logout'])->middleware('auth:sanctum');
```

### 3. Issue Dual-Mode Tokens in Your Controller

Use `Omni::issueTokenResponse()` to preserve all dual-mode token delivery (HttpOnly cookies for web browsers and Bearer tokens for mobile apps):

```php
// app/Http/Controllers/Auth/CustomLoginController.php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use KaziOmar\OmniAuth\Facades\Omni;

class CustomLoginController extends Controller
{
    public function login(Request $request)
    {
        $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required', 'string'],
        ]);

        $user = User::where('email', $request->email)->first();

        if (! $user || ! Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['Invalid credentials provided.'],
            ]);
        }

        // Custom Business Logic: Check Account Suspension
        if ($user->is_suspended) {
            return response()->json([
                'status' => 'error',
                'message' => 'Your account has been suspended. Please contact support.',
            ], 403);
        }

        // Custom Business Logic: Verify Tenant Membership
        if ($user->tenant_id !== $request->header('X-Tenant-ID')) {
            return response()->json(['message' => 'Unauthorized tenant context.'], 401);
        }

        // Deliver Dual-Mode Tokens via OmniAuth Engine
        return Omni::issueTokenResponse(
            $user, 
            $request, 
            message: 'Welcome back!', 
            status: 200
        );
    }

    public function logout(Request $request)
    {
        // Revoke token and clear HttpOnly cookie
        return Omni::logout($request);
    }
}
```

---

## Custom Registration Validation Rules

By default, OmniAuth validates `name`, `email`, and `password`. If you collect additional fields such as `phone`, `organization`, or `terms_accepted`, specify custom validation rules in `config/omni-auth.php`:

```php
// config/omni-auth.php

'registration' => [
    'auto_login' => env('OMNI_REGISTRATION_AUTO_LOGIN', true),
    'default_role' => 'customer',
    'rules' => [
        'name' => ['required', 'string', 'max:255'],
        'email' => ['required', 'string', 'email', 'max:255', 'unique:users,email'],
        'phone' => ['required', 'string', 'max:20', 'unique:users,phone'],
        'company' => ['nullable', 'string', 'max:150'],
        'terms' => ['required', 'accepted'],
        'password' => ['required', 'string', 'min:8', 'confirmed'],
    ],
],
```

Any validated attributes matching your `$user->fillable` array are automatically persisted during registration.

---

## Custom User JSON Resource

OmniAuth formats the user object in `/api/auth/me`, `/login`, and `/register` using `OmniUserResource`. To inject custom attributes, relations, or Spatie role transformations:

```php
// app/Http/Resources/CustomUserResource.php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class CustomUserResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'email' => $this->email,
            'avatar_url' => $this->avatar_url ?? 'https://gravatar.com/avatar/' . md5($this->email),
            'two_factor_active' => $this->hasTwoFactorEnabled(),
            'active_devices_count' => $this->devices()->count(),
            'created_at' => $this->created_at->toISOString(),
        ];
    }
}
```

Register your resource in `config/omni-auth.php`:

```php
// config/omni-auth.php

'user_resource' => \App\Http\Resources\CustomUserResource::class,
```

---

## Event-Driven Architecture (Custom Notifications & SMS)

OmniAuth dispatches clean Laravel events whenever critical security milestones happen. You can register listeners in your application to send customized emails, Twilio SMS, or Slack alerts.

| Event Class | Dispatched When | Payload |
|---|---|---|
| `PasswordResetOtpRequested` | User requests a password reset code | `$event->user`, `$event->otp` |
| `MagicLinkRequested` | User requests a passwordless magic link | `$event->user`, `$event->token`, `$event->url` |
| `TwoFactorFallbackOtpRequested` | User requests an emergency SMS/email 2FA code | `$event->user`, `$event->otp` |
| `EmailVerificationRequested` | User initiates email address verification | `$event->user`, `$event->token`, `$event->url` |
| `AccountDeleted` | User initiates self-service account deletion | `$event->user` |

### Example: Send SMS OTP via Twilio

```php
// app/Listeners/SendPasswordResetSms.php

namespace App\Listeners;

use KaziOmar\OmniAuth\Events\PasswordResetOtpRequested;
use Twilio\Rest\Client as TwilioClient;

class SendPasswordResetSms
{
    public function handle(PasswordResetOtpRequested $event): void
    {
        $user = $event->user;
        $otp = $event->otp;

        if ($user->phone) {
            $twilio = new TwilioClient(config('services.twilio.sid'), config('services.twilio.token'));
            $twilio->messages->create($user->phone, [
                'from' => config('services.twilio.from'),
                'body' => "Your security code is: {$otp}. It expires in 15 minutes.",
            ]);
        }
    }
}
```

Register your listener in `app/Providers/EventServiceProvider.php` (or `AppServiceProvider.php` in Laravel 11/12):

```php
use App\Listeners\SendPasswordResetSms;
use Illuminate\Support\Facades\Event;
use KaziOmar\OmniAuth\Events\PasswordResetOtpRequested;

Event::listen(
    PasswordResetOtpRequested::class,
    SendPasswordResetSms::class,
);
```

---

## Omni Facade API Reference

The `Omni` facade provides static access to all authentication sub-managers:

| Method | Return Type | Description |
|---|---|---|
| `Omni::attempt(array $credentials, ?Request $request)` | `JsonResponse` | Executes credential verification, rate-limiting, and dual-mode token delivery. |
| `Omni::issueTokenResponse($user, ?Request $request)` | `JsonResponse` | Issues access/refresh tokens and associates active device tracking. |
| `Omni::refresh(?Request $request)` | `JsonResponse` | Rotates the refresh token and issues a fresh access token. |
| `Omni::logout(?Request $request, bool $allDevices = false)` | `JsonResponse` | Revokes current token and clears HttpOnly authentication cookies. |
| `Omni::me(?Request $request)` | `JsonResponse` | Returns the formatted user resource with active roles and permissions. |
| `Omni::isMobile(?Request $request)` | `bool` | Returns `true` if request originates from Flutter, React Native, or mobile header. |
| `Omni::isWeb(?Request $request)` | `bool` | Returns `true` if request originates from a web browser. |
| `Omni::devices()` | `DeviceManager` | Direct access to device sessions, IP tracking, and FCM push tokens. |
| `Omni::twoFactor()` | `TwoFactorManager` | Direct access to TOTP generation, clock drift verification, and recovery codes. |
| `Omni::social()` | `SocialAuthManager` | Direct access to OAuth redirect generation and mobile token validation. |
| `Omni::passwordReset()` | `PasswordResetManager` | Direct access to cryptographic OTP hashing and password strength verification. |

### Practical Facade Examples

The table below demonstrates the 5 most common headless workflows you can copy-paste directly into your custom controllers:

#### 1. One-Line Headless Login
Authenticate credentials directly with full rate-limiting and dual-mode cookie/token delivery:

```php
use Illuminate\Http\Request;
use KaziOmar\OmniAuth\Facades\Omni;

public function login(Request $request)
{
    // Verifies credentials, guards against brute-force attacks, and delivers tokens
    return Omni::attempt($request->only('email', 'password'), $request);
}
```

#### 2. Custom Business Logic & Manual Token Issuance
Execute enterprise domain checks (e.g. account suspension, organization tenancy, billing) before issuing tokens:

```php
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use KaziOmar\OmniAuth\Facades\Omni;

public function customAuthenticate(Request $request)
{
    $user = User::where('email', $request->email)->firstOrFail();

    if (! Hash::check($request->password, $user->password)) {
        return response()->json(['message' => 'Invalid credentials.'], 401);
    }

    // Custom Domain Check: Account Suspension
    if ($user->is_suspended) {
        return response()->json(['message' => 'Account is suspended.'], 403);
    }

    // Deliver dual-mode tokens (SameSite HttpOnly cookies for Web, Bearer for Mobile)
    return Omni::issueTokenResponse(
        $user, 
        $request, 
        message: 'Welcome back!', 
        status: 200
    );
}
```

#### 3. Client Environment Detection
Branch logic conditionally based on whether the caller is a mobile app (Flutter / React Native) or a Web SPA:

```php
use Illuminate\Http\Request;
use KaziOmar\OmniAuth\Facades\Omni;

public function handleClientRedirect(Request $request)
{
    if (Omni::isMobile($request)) {
        // Return deep-link URI scheme for mobile clients (e.g., myapp://auth/callback)
        return response()->json(['redirect' => 'myapp://auth/callback']);
    }

    // Fallback for Web SPA clients
    return response()->json(['redirect' => config('app.frontend_url') . '/dashboard']);
}
```

#### 4. Session Revocation (Current Device vs. All Devices)
Single-device sign-out vs. global security kill-switch:

```php
use Illuminate\Http\Request;
use KaziOmar\OmniAuth\Facades\Omni;

// Sign out current device only (clears HttpOnly cookie & purges Sanctum token)
return Omni::logout($request);

// Global Security Sign-Out: Revoke all tokens across all active phones, laptops, and tablets
return Omni::logout($request, allDevices: true);
```

#### 5. Direct Sub-Manager Invocation
Directly query TOTP 2FA status or inspect user devices without going through HTTP endpoints:

```php
use KaziOmar\OmniAuth\Facades\Omni;

// Check if user has confirmed TOTP two-factor authentication
$is2faActive = Omni::twoFactor()->isEnabled($user);

// Inspect all active tracked devices for the user
$devices = Omni::devices()->all($user);

// Rotate sliding refresh token manually in custom controller
return Omni::refresh($request);
```
