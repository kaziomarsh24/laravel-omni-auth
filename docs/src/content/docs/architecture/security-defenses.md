---
title: Security Defenses
description: Deep dive into the battle-tested security architecture and vulnerability mitigations.
---

OmniAuth is engineered with defense-in-depth principles. Rather than relying on simple controller validation, security checks are enforced across service managers, middleware guards, and database schemas.

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

    // Refresh tokens are strictly prohibited from authenticating general API routes
    if ($token->can('refresh') && ! request()->is('*/auth/refresh')) {
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
    // Constant-time dummy verification
    Hash::check($password, '$2y$10$e8wZ3oIqK8mD4V2Y0J6N7eX1wZ9y8x7v6u5t4s3r2q1p0o9n8m7l6');
    return null;
}
```

Whether an email exists or not, the server always executes a full bcrypt operation, keeping response times statistically identical (~235ms vs ~259ms).

---

## 4. Strict URL Whitelisting & Open Redirect Defense

### The Problem
Password reset links and OAuth callbacks accept destination URLs. Attackers use URL authority bypasses to trick parsers:
- `https://evil.com\.app.example.com` (backslash tricks)
- `http://evil.com\@localhost` (userinfo credentials syntax)

### The Mitigation
In `PasswordResetManager::validateRedirectUrl()`:
- URLs containing `\` or `@` characters are instantly rejected with HTTP 422.
- The target hostname is parsed and verified against `config('app.url')` and an explicit allowed hosts whitelist.
- Subdomain wildcards are strictly validated against period-delimited host boundaries.
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
