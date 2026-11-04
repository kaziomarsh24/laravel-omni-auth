---
title: Complete API Reference
description: Comprehensive reference documentation for all 29 OmniAuth endpoints.
---

This document provides complete technical specifications for all 29 built-in API endpoints registered by Laravel OmniAuth.

---

## Quick Reference Table

| Category | Method | Path | Route Name | Auth Required |
| :--- | :--- | :--- | :--- | :--- |
| **Core** | `POST` | `/api/auth/login` | `omni.login` | No |
| **Core** | `POST` | `/api/auth/register` | `omni.register` | No |
| **Core** | `POST` | `/api/auth/refresh` | `omni.refresh` | Refresh Token |
| **Core** | `POST` | `/api/auth/logout` | `omni.logout` | Yes (`omni.auth`) |
| **Core** | `GET` | `/api/auth/me` | `omni.me` | Yes (`omni.auth`) |
| **Devices** | `GET` | `/api/auth/devices` | `omni.devices.index` | Yes (`omni.auth`) |
| **Devices** | `DELETE` | `/api/auth/devices/{id}` | `omni.devices.destroy` | Yes (`omni.auth`) |
| **Devices** | `POST` | `/api/auth/devices/logout-others` | `omni.devices.logout_others` | Yes (`omni.auth`) |
| **Devices** | `POST` | `/api/auth/devices/fcm` | `omni.devices.fcm` | Yes (`omni.auth`) |
| **Two-Factor** | `POST` | `/api/auth/2fa/challenge` | `omni.2fa.challenge` | Challenge Token |
| **Two-Factor** | `POST` | `/api/auth/2fa/fallback-otp` | `omni.2fa.fallback_otp` | Challenge Token |
| **Two-Factor** | `POST` | `/api/auth/2fa/setup` | `omni.2fa.setup` | Yes (`omni.auth`) |
| **Two-Factor** | `POST` | `/api/auth/2fa/confirm` | `omni.2fa.confirm` | Yes (`omni.auth`) |
| **Two-Factor** | `POST` | `/api/auth/2fa/recovery-codes` | `omni.2fa.recovery_codes` | Yes (`omni.auth`) |
| **Two-Factor** | `POST` | `/api/auth/2fa/disable` | `omni.2fa.disable` | Yes (`omni.auth`) |
| **Social** | `POST` | `/api/auth/social/exchange` | `omni.social.exchange` | No |
| **Social** | `GET` | `/api/auth/social/{provider}/redirect` | `omni.social.redirect` | No |
| **Social** | `GET\|POST` | `/api/auth/social/{provider}/callback` | `omni.social.callback` | No |
| **Social** | `GET` | `/api/auth/social/accounts` | `omni.social.accounts` | Yes (`omni.auth`) |
| **Social** | `DELETE` | `/api/auth/social/{provider}` | `omni.social.unlink` | Yes (`omni.auth`) |
| **Password** | `POST` | `/api/auth/forgot-password` | `omni.password.forgot` | No |
| **Password** | `POST` | `/api/auth/verify-reset-otp` | `omni.password.verify_otp` | No |
| **Password** | `POST` | `/api/auth/reset-password` | `omni.password.reset` | No |
| **Magic Link** | `POST` | `/api/auth/magic-link` | `omni.magic.send` | No |
| **Magic Link** | `GET\|POST` | `/api/auth/magic-link/verify` | `omni.magic.verify` | No |
| **Lifecycle** | `GET\|POST` | `/api/auth/email/verify/{id}/{hash}` | `omni.email.verify` | Signed Route |
| **Lifecycle** | `POST` | `/api/auth/email/verify` | `omni.email.verify_otp` | Yes (`omni.auth`) |
| **Lifecycle** | `POST` | `/api/auth/email/resend` | `omni.email.resend` | Yes (`omni.auth`) |
| **Lifecycle** | `DELETE` | `/api/auth/account` | `omni.account.delete` | Yes (`omni.auth`) |

---

## 1. Core Authentication

### `POST /api/auth/login`
Authenticates user with email/username and password.

- **Headers**:
  - `Accept: application/json`
  - `X-Client-Type: mobile` (optional, delivers tokens in body instead of cookies)
- **Request Body**:
```json
{
  "email": "user@example.com",
  "password": "Password123!"
}
```
- **Responses**:
  - `200 OK`: Standard login success (tokens returned in JSON for mobile or cookies set for web).
  - `200 OK` (`status: "requires_2fa"`): Two-factor authentication required; returns `challenge_token`.
  - `401 Unauthorized`: Invalid credentials (constant-time response).
  - `422 Unprocessable Entity`: Validation failure.
  - `429 Too Many Requests`: Rate limit exceeded.

---

### `POST /api/auth/register`
Creates a new user account.

- **Request Body**:
```json
{
  "name": "Jane Doe",
  "email": "jane@example.com",
  "password": "Password123!",
  "password_confirmation": "Password123!"
}
```
- **Responses**:
  - `201 Created`: User created and automatically logged in.
  - `422 Unprocessable Entity`: Validation failure or existing email.

---

### `POST /api/auth/refresh`
Rotates a sliding refresh token and returns a new access token.

- **Headers**:
  - `Authorization: Bearer <refresh_token>` (for mobile clients)
- **Request Body** (optional if provided in header or cookie):
```json
{
  "refresh_token": "2|k9m..."
}
```
- **Responses**:
  - `200 OK`: New access token and rotated refresh token.
  - `401 Unauthorized`: Token expired, invalid, or already consumed.

---

### `POST /api/auth/logout`
Terminates the current authenticated session and revokes tokens.

- **Middleware**: `omni.auth`
- **Responses**:
  - `200 OK`: Session terminated.
  - `401 Unauthorized`: Unauthenticated.

---

### `GET /api/auth/me`
Retrieves the profile of the currently authenticated user.

- **Middleware**: `omni.auth`
- **Responses**:
  - `200 OK`: Returns user profile resource, including roles/permissions if enabled.

---

## 2. Device Management

### `GET /api/auth/devices`
Lists all active sessions linked to the user account.

- **Middleware**: `omni.auth`
- **Responses**:
  - `200 OK`: Array of device records with `is_current` boolean indicator.

---

### `DELETE /api/auth/devices/{id}`
Revokes a specific remote device session.

- **Middleware**: `omni.auth`
- **Responses**:
  - `200 OK`: Device and associated refresh token revoked.
  - `404 Not Found`: Device ID does not belong to user.

---

### `POST /api/auth/devices/logout-others`
Revokes all active sessions except the one making the request.

- **Middleware**: `omni.auth`
- **Responses**:
  - `200 OK`: Other device sessions terminated.

---

### `POST /api/auth/devices/fcm`
Updates the push notification token (FCM/APNS) for the current device.

- **Middleware**: `omni.auth`
- **Request Body**:
```json
{
  "fcm_token": "fcm_token_string..."
}
```
- **Responses**:
  - `200 OK`: Token updated.

---

## 3. Two-Factor Authentication

### `POST /api/auth/2fa/challenge`
Verifies a 6-digit TOTP code or recovery code during login (accepts `two_factor_token` or `challenge_token`).

- **Request Body**:
```json
{
  "two_factor_token": "2fa_challenge_abc...",
  "code": "123456"
}
```
- **Responses**:
  - `200 OK`: Challenge completed; returns access and refresh tokens.
  - `422 Unprocessable Entity`: Invalid or expired challenge token, or incorrect code.

---

### `POST /api/auth/2fa/fallback-otp`
Requests an emergency SMS or email OTP fallback when authenticator is unavailable (accepts `two_factor_token` or `challenge_token`).

- **Request Body**:
```json
{
  "two_factor_token": "2fa_challenge_abc..."
}
```

---

### `POST /api/auth/2fa/setup`
Initiates TOTP configuration. Requires password re-authentication.

- **Middleware**: `omni.auth`
- **Request Body**:
```json
{
  "password": "Password123!"
}
```
- **Responses**:
  - `200 OK`: Returns base32 secret, OTPAuth URI, SVG QR code, and plaintext recovery codes.

---

### `POST /api/auth/2fa/confirm`
Confirms and activates TOTP 2FA using code from authenticator app.

- **Middleware**: `omni.auth`
- **Request Body**:
```json
{
  "code": "123456"
}
```

---

### `POST /api/auth/2fa/recovery-codes`
Generates fresh backup recovery codes. Requires password re-authentication.

- **Middleware**: `omni.auth`
- **Request Body**:
```json
{
  "password": "Password123!"
}
```

---

### `POST /api/auth/2fa/disable`
Disables Two-Factor Authentication. Requires password re-authentication.

- **Middleware**: `omni.auth`
- **Request Body**:
```json
{
  "password": "Password123!"
}
```

---

## 4. Social Authentication

### `POST /api/auth/social/exchange`
Direct native mobile ID token exchange for Google and Apple.

- **Request Body**:
```json
{
  "provider": "apple",
  "id_token": "eyJhbGciOiJSUzI1Ni..."
}
```
- **Responses**:
  - `200 OK`: Returns user profile and session tokens.
  - `200 OK` (`status: "requires_2fa"`): Returns challenge token if user has 2FA enabled.
  - `400 Bad Request`: Invalid or unverified token.

---

### `GET /api/auth/social/{provider}/redirect`
Redirects browser to OAuth provider authorization screen.

- **Parameters**: `provider` (`google`, `apple`, `github`, `facebook`)

---

### `GET|POST /api/auth/social/{provider}/callback`
Handles OAuth 2.0 callback from provider. Requires valid `state` parameter.

---

### `GET /api/auth/social/accounts`
Lists all social identities linked to the authenticated user.

- **Middleware**: `omni.auth`

---

### `DELETE /api/auth/social/{provider}`
Unlinks a social identity from the user account.

- **Middleware**: `omni.auth`

---

## 5. Password Reset

### `POST /api/auth/forgot-password`
Dispatches a password reset link or 6-digit OTP code to the provided email.

- **Request Body**:
```json
{
  "email": "user@example.com",
  "redirect_url": "https://app.example.com/reset-password"
}
```

---

### `POST /api/auth/verify-reset-otp`
Validates a 6-digit password reset OTP and exchanges it for a temporary reset token (accepts `otp` or `code`).

- **Request Body**:
```json
{
  "email": "user@example.com",
  "otp": "654321"
}
```

---

### `POST /api/auth/reset-password`
Updates password using reset token.

- **Request Body**:
```json
{
  "email": "user@example.com",
  "token": "reset_token_here...",
  "password": "NewSecurePassword123!",
  "password_confirmation": "NewSecurePassword123!"
}
```

---

## 6. Passwordless Magic Links

### `POST /api/auth/magic-link`
Generates and emails a single-use login link.

- **Request Body**:
```json
{
  "email": "user@example.com",
  "redirect_url": "https://app.example.com/auth/callback"
}
```

---

### `GET|POST /api/auth/magic-link/verify`
Consumes the magic link token and authenticates the session.

- **Request Body / Query Parameter**:
```json
{
  "token": "magic_token_string..."
}
```

---

## 7. Lifecycle & Verification

### `GET|POST /api/auth/email/verify/{id}/{hash}`
Verifies email address via cryptographically signed route.

---

### `POST /api/auth/email/verify`
Verifies email address using 6-digit OTP code (accepts `otp` or `code`).

- **Middleware**: `omni.auth`
- **Request Body**:
```json
{
  "otp": "819234"
}
```

---

### `POST /api/auth/email/resend`
Resends the email verification notification.

- **Middleware**: `omni.auth`

---

### `DELETE /api/auth/account`
Permanently deletes the authenticated user account and cascades credential revocation.

- **Middleware**: `omni.auth`
- **Request Body** (required if account has a password):
```json
{
  "password": "Password123!"
}
```
