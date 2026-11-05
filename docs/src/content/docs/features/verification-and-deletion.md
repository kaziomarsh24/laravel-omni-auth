---
title: Verification & Account Deletion
description: Signed email verification, brute-force protected OTPs, and GDPR-compliant self-service account deletion.
---

OmniAuth includes complete flows for email verification and self-service account deletion.

---

## Email Verification

:::note[Registration Flow & Email Verification Architecture]
Modern SaaS and mobile applications (e.g., GitHub, Twitter/X, Spotify, Netflix) face a critical tradeoff between user drop-off and account security. OmniAuth accommodates both industry architectures:

1. **Immediate Login (Default):**
   - By default (`'auto_login' => true`), upon calling [`POST /api/auth/register`](/laravel-omni-auth/reference/api-reference/#post-apiauthregister), OmniAuth immediately returns authentication tokens (or sets HttpOnly cookies) and dispatches a background verification email.
   - The user is logged in immediately (`email_verified_at = null`), allowing them to explore onboarding tours or public app areas.
   - Sensitive or billing endpoints can be protected using the `omni.auth` and `verified` middleware (`Route::middleware(['omni.auth', 'verified'])`), which blocks unverified users with HTTP 403 until they complete verification.

2. **Strict Verification-First Flow (Regulated / High-Security Apps):**
   - If your application strictly requires verification before any session is issued (e.g., banking, healthcare, government), set `'auto_login' => false` in `config/omni-auth.php` (or `OMNI_REGISTRATION_AUTO_LOGIN=false` in `.env`).
   - In this mode, [`POST /api/auth/register`](/laravel-omni-auth/reference/api-reference/#post-apiauthregister) creates the user record and dispatches the verification link/OTP, but returns **zero tokens** and sets **zero cookies**. The client must guide the user to verify their email before they can authenticate via [`POST /api/auth/login`](/laravel-omni-auth/reference/api-reference/#post-apiauthlogin).
:::

OmniAuth supports two methods of email verification: signed URLs (for web email clients) and 6-digit OTP codes (for mobile apps).

### 1. Cryptographically Signed URL Verification

When a user registers or requests verification, an email with a signed route is generated using Laravel's URL signer. See [`GET /api/auth/email/verify/{id}/{hash}`](/laravel-omni-auth/reference/api-reference/#getpost-apiauthemailverifyidhash) in the API Reference.

```http
GET /api/auth/email/verify/42/bf892d...?expires=1730000000&signature=e7a8...
Accept: application/json
```

- OmniAuth strictly verifies the URL signature (`URL::hasValidSignature()`).
- If the signature is valid and has not expired, the user's `email_verified_at` timestamp is updated, and the `Verified` event is fired.

---

### 2. Mobile 6-Digit OTP Verification

Mobile applications often present a 6-digit PIN screen rather than directing users through external browser links:

```http
POST /api/auth/email/verify
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "otp": "849201"
}
```

Response:
```json
{
  "ok": true,
  "message": "Email address has been verified successfully."
}
```

#### Brute-Force Rate Limiting & Anti-Enumeration Defense
- The OTP endpoint enforces a strict rate limit of 5 attempts per window.
- If an invalid code is supplied or the code does not exist, OmniAuth returns a uniform HTTP 422 response (`{"ok": false, "message": "Invalid, expired, or tampered verification link or code."}`) to prevent user identification or OTP brute-forcing.

---

### 3. Resend Verification Request

```http
POST /api/auth/email/resend
Authorization: Bearer <access_token>
```

Response:
```json
{
  "ok": true,
  "message": "Email verification code has been dispatched."
}
```

:::tip[Customizing Verification Delivery]
When verification codes or signed links are dispatched, OmniAuth automatically sends a Markdown email containing both the verification passcode and a signed URL. To customize this email or deliver codes via Twilio SMS or WhatsApp, see the [Notifications & Alerts Guide](/laravel-omni-auth/features/notifications/).
:::

---

## Self-Service Account Deletion (GDPR & Apple App Store)

:::tip[Apple App Store Guideline 5.1.1(v) Compliance]
Apple App Store Review Guidelines strictly mandate that any mobile application that supports account creation must also allow users to initiate deletion of their account from within the app.

[`DELETE /api/auth/account`](/laravel-omni-auth/reference/api-reference/#delete-apiauthaccount) fully satisfies Guideline 5.1.1(v). It revokes all active tokens, removes tracked device records, deletes associated social accounts, and permanently deletes or soft-deletes the user record in full compliance with Apple and GDPR requirements.
:::

OmniAuth enables users to permanently delete their account and associated authentication credentials via [`DELETE /api/auth/account`](/laravel-omni-auth/reference/api-reference/#delete-apiauthaccount).

### Password & 2FA Authenticated Deletion
For accounts with a user-set password, confirming the current password is required. Additionally, if Two-Factor Authentication is active on the account, confirming with a valid TOTP code (or emergency recovery code) is strictly enforced:

```http
DELETE /api/auth/account
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "password": "UserCurrentPassword123!",
  "code": "849201"
}
```

Response:
```json
{
  "ok": true,
  "message": "Your account has been deleted permanently along with all active sessions."
}
```

### Deletion for Social-Only Accounts
If an account was registered exclusively through an external OAuth provider (Google or Apple) and possesses no local password, password confirmation is bypassed. However, if the social user enabled 2FA, their 2FA code is still strictly required. If they have neither a password nor 2FA, deletion proceeds with an empty body in full compliance with Apple App Store Guideline 5.1.1(v).

### Cascading Cleanup
Upon deletion:
1. All active Sanctum personal access tokens and refresh tokens are deleted.
2. All tracked device sessions in `auth_devices` are purged.
3. Linked OAuth identities in `auth_social_accounts` are deleted.
4. Active TOTP secrets and recovery codes in `auth_two_factor` are erased.
5. The user record is deleted (or soft-deleted if using `SoftDeletes`).
6. The `AccountDeleted` event is fired (`KaziOmar\OmniAuth\Events\AccountDeleted`).
7. OmniAuth automatically sends a farewell confirmation email notifying the user that all personal data, sessions, and tokens have been permanently removed. See [Notifications & Alerts](/laravel-omni-auth/features/notifications/) to configure or customize this message.
