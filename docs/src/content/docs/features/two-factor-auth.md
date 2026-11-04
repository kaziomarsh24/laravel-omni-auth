---
title: Two-Factor Authentication (TOTP)
description: RFC 6238 time-based one-time password implementation, encrypted secrets, and recovery codes.
---

OmniAuth includes full-featured Two-Factor Authentication (2FA) compatible with standard authenticator applications (Google Authenticator, Apple Passwords, 1Password, Authy).

---

## Architecture & Storage Security

- **Encrypted Secrets**: TOTP secrets are encrypted at rest using Laravel's application key via `Crypt::encryptString()`. If the database is compromised, secrets cannot be read without the application master key.
- **Hashed Recovery Codes**: Backup recovery codes are hashed using SHA-256 before being stored in the database. Plaintext recovery codes are only displayed once to the user during setup.
- **Challenge Isolation**: During initial login, if 2FA is active, access tokens are withheld. The client receives a restricted `2fa-challenge` token valid only for calling the verify endpoint.

:::warning[Server NTP Clock Synchronization]
TOTP verification strictly implements **RFC 6238** (30-second time-based windows). Although OmniAuth permits a standard 1-step clock drift allowance (±30 seconds), if your Docker container, local VM, or cloud server's system clock deviates from atomic time by more than 60 seconds, valid Google Authenticator codes will be rejected.

Ensure your host or server environment has active **NTP (Network Time Protocol)** synchronization (`systemd-timesyncd`, `chrony`, or `ntp`).
:::

---

## Activation Flow

```text
User                      App Client                     OmniAuth Backend
 |                            |                                 |
 |-- Enable 2FA ------------->|-- POST /api/auth/2fa/setup ---->| Validates password
 |                            |   { "password": "..." }         | Generates base32 secret
 |                            |<-- { secret, qr_code, ... } ----| Stores encrypted secret
 |                            |                                 |
 |-- Scan QR / Enter Code --->|-- POST /api/auth/2fa/confirm -->| Validates TOTP code
 |                            |   { "code": "123456" }          | Sets confirmed_at
 |                            |<-- { "status": "confirmed" } ---|
```

### 1. Initiate Setup
The user must provide their current password to begin setup:

```http
POST /api/auth/2fa/setup
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "password": "UserCurrentPassword123!"
}
```

Response:
```json
{
  "ok": true,
  "message": "Two-factor setup initiated. Confirm with a valid code from your authenticator app to enable.",
  "data": {
    "secret": "JBSWY3DPEHPK3PXP",
    "qr_code_url": "otpauth://totp/MyApp:jane@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp",
    "svg_qr": "<svg ...></svg>",
    "recovery_codes": [
      "A1B2-C3D4",
      "E5F6-G7H8",
      "I9J0-K1L2"
    ]
  }
}
```

### 2. Confirm Setup
The user enters the 6-digit code shown in their authenticator app to verify that setup was successful:

```http
POST /api/auth/2fa/confirm
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "code": "482910"
}
```

Response:
```json
{
  "ok": true,
  "message": "Two-factor authentication has been confirmed and enabled."
}
```

---

## Login Authentication Challenge

When a user with 2FA enabled logs in via credentials, social exchange, or magic link, OmniAuth returns a challenge response:

```json
{
  "ok": true,
  "message": "Two-factor authentication is required.",
  "data": {
    "requires_2fa": true,
    "two_factor_token": "2fa_challenge_9a8b7c6d...",
    "expires_in": 300
  }
}
```

The client then prompts the user for their 6-digit code and calls the challenge resolution endpoint (accepts `two_factor_token` or `challenge_token`):

```http
POST /api/auth/2fa/challenge
Content-Type: application/json

{
  "two_factor_token": "2fa_challenge_9a8b7c6d...",
  "code": "482910"
}
```

Once validated:
- The challenge token is destroyed.
- Real `access_token` and `refresh_token` instances are issued.
- The `UserLoggedIn` event is fired.

### Recovery Code Fallback

If the user loses access to their authenticator app, they can pass any of their unused 8-character recovery codes in the `code` field. OmniAuth hashes the code, verifies the match, and burns that specific recovery code so it cannot be reused.

---

## Management Endpoints

### Regenerating Recovery Codes
Requires password confirmation. Returns eight fresh codes and invalidates all prior recovery codes:

```http
POST /api/auth/2fa/recovery-codes
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "password": "UserCurrentPassword123!"
}
```

### Disabling 2FA
Requires password confirmation. Wipes the TOTP secret and recovery codes:

```http
POST /api/auth/2fa/disable
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "password": "UserCurrentPassword123!"
}
```
