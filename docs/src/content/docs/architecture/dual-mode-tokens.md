---
title: Dual-Mode Authentication
description: Architecture of unified cookie and bearer token delivery for Web SPAs and Mobile clients.
---

Building modern applications typically requires supporting two distinct client architectures with fundamentally incompatible token storage models:

1. **Web SPAs (Next.js, React, Vue, Svelte)**: Storing tokens in `localStorage` or `sessionStorage` leaves them permanently vulnerable to Cross-Site Scripting (XSS). An attacker who can execute arbitrary JavaScript can exfiltrate stored tokens. Web clients should use encrypted, `HttpOnly`, `SameSite` cookies with CSRF defense.
2. **Mobile Apps (Flutter, iOS Swift, Android Kotlin, React Native)**: Native mobile operating systems do not operate within a browser cookie jar. They possess secure hardware-backed keychains (`Keychain` on iOS, `KeyStore` / `EncryptedSharedPreferences` on Android) and expect standard `Authorization: Bearer <token>` headers.

Laravel OmniAuth bridges this gap by supporting both transport layers from a single set of API endpoints.

---

## Token Delivery Flow

The authentication pipeline automatically determines token delivery semantics using request metadata:

```text
                  +-----------------------------+
                  | Incoming Login / Auth Route |
                  +-----------------------------+
                                 |
                     Is X-Client-Type: mobile
                     or mobile User-Agent detected?
                                 |
                 +---------------+---------------+
                 |                               |
              [ YES ]                         [ NO ]
                 |                               |
                 v                               v
    +-------------------------+     +-------------------------+
    | Mobile Delivery Mode    |     | Web / SPA Delivery Mode |
    +-------------------------+     +-------------------------+
    | Returns tokens in JSON: |     | Sets HttpOnly Cookies:  |
    | - data.access_token     |     | - omni_access_token     |
    | - data.refresh_token    |     | - omni_refresh_token    |
    |                         |     |                         |
    | Client stores tokens in |     | Browser automatically   |
    | Flutter SecureStorage   |     | attaches cookies on     |
    | or React Native Keytar  |     | subsequent requests     |
    +-------------------------+     +-------------------------+
```

---

## Web Client Implementation Details

When a browser makes a request to `/api/auth/login`:
- OmniAuth sets an `omni_access_token` cookie with `HttpOnly: true`, `SameSite: Lax`, and `Secure: true` (in production).
- The token payload is omitted from the JSON body (`access_token: null`) to prevent client-side JavaScript from accidentally copying it into `localStorage`.
- A second sliding `omni_refresh_token` cookie is set with path `/api/auth/refresh`.
- **CSRF Isolation**: When authenticating via cookies, state-changing requests (POST, PUT, DELETE) require a custom header (such as `X-Requested-With: XMLHttpRequest` or `X-XSRF-TOKEN`). Browsers prohibit cross-origin scripts from forging custom headers, defeating cross-site request forgery without requiring complex session synchronization.

---

## Mobile Client Implementation Details

When a mobile app makes a request:
- The app passes `X-Client-Type: mobile` (or a native User-Agent).
- OmniAuth omits Set-Cookie headers.
- The JSON response contains:

```json
{
  "ok": true,
  "message": "Authenticated successfully.",
  "data": {
    "user": {
      "id": 42,
      "name": "Jane Developer",
      "email": "jane@example.com"
    },
    "tokens": {
      "access_token": "1|qX8y...",
      "refresh_token": "2|mK9z...",
      "token_type": "Bearer",
      "expires_in": 900
    }
  }
}
```

- Mobile clients store the `access_token` and `refresh_token` in secure device storage (e.g., `flutter_secure_storage` or Android KeyStore).
- On subsequent requests, the app attaches:

```http
Authorization: Bearer 1|qX8y...
```

---

## Comparison Matrix

| Property | Web SPA Mode | Mobile Client Mode |
| :--- | :--- | :--- |
| **Header** | Default (or `X-Client-Type: web`) | `X-Client-Type: mobile` |
| **Token Delivery** | `Set-Cookie` (`HttpOnly`, `SameSite`) | JSON Body (`data.tokens`) |
| **Storage Target** | Browser Cookie Jar | Keychain / EncryptedSharedPreferences |
| **XSS Vulnerability** | Immune (JavaScript cannot read cookie) | Immune (Native sandbox isolation) |
| **CSRF Defense** | SameSite + Custom Header requirement | Native apps are exempt from browser CSRF |
| **Token Lifespans** | 15 min access / 30 day refresh | 15 min access / 30 day refresh |
