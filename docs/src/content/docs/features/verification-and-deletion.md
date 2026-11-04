---
title: Verification & Account Deletion
description: Signed email verification, brute-force protected OTPs, and GDPR-compliant self-service account deletion.
---

OmniAuth includes complete flows for email verification and self-service account deletion.

---

## Email Verification

OmniAuth supports two methods of email verification: signed URLs (for web email clients) and 6-digit OTP codes (for mobile apps).

### 1. Cryptographically Signed URL Verification

When a user registers or requests verification, an email with a signed route is generated using Laravel's URL signer.

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

---

## Self-Service Account Deletion (GDPR)

OmniAuth enables users to permanently delete their account and associated authentication credentials via `DELETE /api/auth/account`.

### Password-Authenticated Deletion
For standard email and password accounts, providing the current password is required:

```http
DELETE /api/auth/account
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
  "message": "Your account has been deleted permanently along with all active sessions."
}
```

### Password-Free Deletion for Social Accounts
If an account was registered exclusively through an external OAuth provider (Google or Apple) and possesses no local password hash (`password === null`), OmniAuth permits account deletion without password confirmation, provided the session carries valid authentication credentials.

### Cascading Cleanup
Upon deletion:
1. All active Sanctum personal access tokens and refresh tokens are deleted.
2. All tracked device sessions in `auth_devices` are purged.
3. Linked OAuth identities in `auth_social_accounts` are deleted.
4. Active TOTP secrets and recovery codes in `auth_two_factor` are erased.
5. The user record is deleted (or soft-deleted if using `SoftDeletes`).
6. The `UserDeleted` event is fired.
