---
title: Security Defenses
description: Overview of the built-in security defenses and vulnerability mitigations in OmniAuth.
---

OmniAuth applies defense-in-depth principles. Security checks are enforced across service classes, middleware guards, and database schemas rather than relying solely on controller validation.

Below is the technical specification of the key defenses implemented in the codebase.

---

## 1. Refresh Token Guard Isolation

### The Problem
Sanctum's default token authenticator validates any active `PersonalAccessToken` regardless of its assigned abilities unless routes explicitly declare `abilities:...` middleware.

### The Mitigation
OmniAuth registers an authentication callback with Sanctum during boot:

```php
Sanctum::authenticateAccessTokensUsing(function (PersonalAccessToken $token, bool $isValid) {
    if (! $isValid) {
        return null;
    }

    // Refresh tokens (bearing issue-access-token ability) cannot authenticate standard API routes
    if (in_array('issue-access-token', (array) $token->abilities, true) && ! request()->is('*/auth/refresh')) {
        return null;
    }

    return $token;
});
```

Any attempt to present a refresh token to a standard API route is rejected at the guard layer before controller execution begins.

---

## 2. Apple & Google RS256 Cryptographic Verification

### The Problem
OAuth providers like Apple issue JSON Web Tokens (JWT) signed with asymmetric RSA keys. Naive JWT parsers often:
- Blindly decode payloads without verifying the cryptographic signature.
- Accept symmetric `alg: HS256` signatures signed using the provider's public key as an HMAC secret.
- Cache empty or malformed JWKS responses during network blips, permanently locking users out.

### The Mitigation
In `SocialAuthManager`, OmniAuth enforces:
1. **Header Validation**: Verifies that the JWT header contains `alg: RS256` and a valid `kid`. Any token declaring `none` or `HS256` triggers an immediate exception.
2. **JWKS Key Matching**: Queries Apple's JWKS endpoint (`https://appleid.apple.com/auth/keys`), isolates the matching `kid`, and converts the RSA modulus (`n`) and exponent (`e`) into a valid PEM format.
3. **Cryptographic Verification**: Calls `openssl_verify()` with `OPENSSL_ALGO_SHA256` to confirm that the payload was authentically signed by Apple's private key.
4. **Defensive Caching**: Successful JWKS responses are cached for 24 hours. If an HTTP call fails or returns an empty key set, the response is explicitly bypassed and never cached.

---

## 3. Constant-Time Timing Attack Defense

### The Problem
When authenticating via email and password, standard lookups query the database first. If the user record is not found, the controller returns immediately. If the user is found, the system runs a computationally expensive bcrypt hash verification.

Attackers measure response times across hundreds of requests to determine which email addresses exist in the database.

### The Mitigation
In `OmniAuthManager`:

```php
if (! $user) {
    // Constant-time dummy verification matching active hasher driver & cost
    Hash::check($password, $this->getDummyPasswordHash());
    return null;
}
```

Whether an email exists or not, the server always executes a full cryptographic hashing operation matching the application's active driver (`bcrypt`, `argon2i`, or `argon2id`).

> **Persistent Cache Recommendation:** To maintain exact timing parity between existing and non-existent accounts, ensure a persistent cache driver (Redis, Memcached, Database) is configured so the generated dummy hash is remembered without per-request overhead.

---

## 4. Strict URL Whitelisting & Open Redirect Defense

### The Problem
Password reset links and OAuth callbacks accept destination URLs. Attackers use URL authority bypasses to trick parsers:
- `https://evil.com\.app.example.com` (backslash tricks)
- `http://evil.com\@localhost` (userinfo credentials syntax)

### The Mitigation
In `PasswordResetManager::validateRedirectUrl()`:
- URLs containing `\` or `@` characters are instantly rejected with HTTP 422.
- The target hostname is parsed and verified for an **exact match** against `config('app.url')` and any hostnames explicitly listed in `config('omni-auth.allowed_redirect_hosts')`.
- Mobile custom deep link schemes (e.g. `myapp://`) are accepted only when declared in `config('omni-auth.magic_link.allowed_schemes')`.
- `localhost` redirects are prohibited in production and staging environments, allowed only when `app.env === 'local'` or `'testing'`.

---

## 5. Case-Insensitive Mass Assignment Prevention

### The Problem
During self-registration, user input may contain sensitive fields (e.g., `role`, `is_admin`). Filtering with `Arr::except($data, ['role', 'is_admin'])` fails if an attacker sends uppercase variants like `{"Is_Admin": true}` or `{"ROLE": "admin"}` if the underlying database collation is case-insensitive.

### The Mitigation
OmniAuth normalizes all input keys to lowercase prior to applying filtering rules:

```php
$normalizedData = [];
foreach ($data as $key => $value) {
    $normalizedData[strtolower($key)] = $value;
}

$safeData = Arr::except($normalizedData, ['role', 'is_admin', 'email_verified_at', 'permissions']);
```

---

## 6. Distributed Rate Limiting

To prevent distributed credential stuffing where attackers use botnets to submit attempts from hundreds of different IP addresses, OmniAuth tracks rate limits on two separate dimensions:

1. **Per-IP Rate Limit**: Up to 5 failed attempts per IP address every 60 seconds.
2. **Global Account Limit**: Up to 20 failed attempts against any single email address across all combined IP addresses within a 15-minute sliding window.

If an account is targeted by a distributed attack, global rate limiting locks the account independently of the attacking IP addresses.

---

## 7. Passwordless Account Re-Auth & GDPR Deletion

### Passwordless Re-Authentication (R2 Mitigation)
When a social-only user (without a local password) initiates two-factor authentication setup or account changes, OmniAuth prevents attackers with a stolen access token from taking over the account by requiring email verification OTP re-authentication (`omni-auth.two_factor.reauth_passwordless`).

### GDPR-Compliant Account Deletion
`DELETE /api/auth/account` enforces complete cascading cleanup of tokens, device records, 2FA credentials, and social links. If the configured User model uses the `Illuminate\Database\Eloquent\SoftDeletes` trait, OmniAuth enforces `forceDelete()` to guarantee full compliance with GDPR Right to Erasure and Apple App Store Guideline 5.1.1(v).
