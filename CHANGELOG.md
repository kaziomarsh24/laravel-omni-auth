# Changelog

All notable changes to `laravel-omni-auth` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Core Dual-Mode Token Engine**: Unified authentication delivering `HttpOnly, SameSite` cookies for web SPAs and `Bearer` tokens with sliding refresh tokens for mobile apps (`X-Client-Type: mobile` or auto User-Agent detection).
- **29 Turnkey Endpoints**: Full API surface across Core Auth (5), Device Sessions (4), TOTP 2FA (6), Social Login (5), Password Reset (3), Magic Links (2), and Email Verification & GDPR Account Deletion (4).
- **Device Management & Push Tokens**: Session tracking table (`auth_devices`) storing IP, User-Agent, platform, FCM/APNS push tokens, and per-device revocation.
- **Two-Factor Authentication (RFC 6238 TOTP)**: Time-based one-time password flow with encrypted secrets (`Crypt::encryptString`), hashed backup recovery codes (`Hash::make` / Bcrypt / Argon2id), and password-authenticated setup/disable.
- **Social Authentication & Mobile Exchange**: OAuth 2.0 web redirect flow alongside native mobile ID token exchange for Google and Apple with cryptographic RS256 JWKS validation.
- **Passwordless Magic Links**: Cryptographically signed single-use login links with 2FA enforcement and strict URL whitelisting.
- **Artisan Commands**:
  - `php artisan omni:install`: Interactive installer publishing configuration and running migrations.
  - `php artisan omni:prune-tokens`: Automated cleanup pruning expired tokens and stale devices (supports `--hours` and `--days`).
- **Astro Starlight Documentation Portal**: Dedicated technical documentation in `/docs` featuring architectural diagrams, security analysis, multi-client integration guides (Next.js, Flutter, Expo), and complete API specifications.
- **Test Suite**: 114 automated unit, integration, and security regression tests with 623 assertions passing across PHP 8.2–8.5 and Laravel 11–13.

### Security
- Added mandatory Two-Factor Authentication (TOTP or Emergency Recovery Code) confirmation upon account deletion for any account with active 2FA.
- Fixed account deletion bypass ensuring users with passwords strictly confirm their password even if social accounts are linked (N1).
- Mitigated orphaned refresh tokens when logging in repeatedly on the same device ID, and ensured single-device logout revokes paired refresh tokens (N2).
- Replaced hardcoded Bcrypt dummy hash with dynamic driver-aware hashing (`getDummyPasswordHash()`) to avoid 500 exceptions on Argon2/Argon2id drivers (N3).
- Added automatic cleanup of attacker 2FA credentials when claiming unverified pre-hijacked accounts via verified social providers (N4).
- Added rate limiting across sensitive re-authentication endpoints (`/2fa/setup`, `/2fa/recovery-codes`, `/2fa/disable`, `/account`) to prevent password brute-forcing (N5).
- Normalized email identifiers before validation and login to prevent unique collision crashes and case-mismatch auth failures (N6).
- Resolved Sanctum global hook ability conflict, allowing custom non-Omni tokens (`['read']`, `['*']`) to authenticate without 401 errors (N7).
- Added live Apple JWKS key rotation refetching on unknown `kid` (N8).
- Enabled seamless 2FA setup and account deletion for passwordless social-only users (N9).
- Added atomic concurrency locks for token rotation, 2FA setup, and social account linking to defeat race conditions (BUG-01 to BUG-09).
- Guard-level refresh token isolation preventing refresh tokens from authenticating regular API routes (`Sanctum::authenticateAccessTokensUsing`).
- Account pre-hijacking prevention: invalidates pre-existing passwords and purges active sessions when linking verified social providers to unverified accounts.
- Constant-time dummy hash verification on non-existent users to defeat timing-based email enumeration.
- Strict redirect URL sanitization preventing open redirects via backslash (`\`) and userinfo (`@`) authority bypasses.
- Case-insensitive mass-assignment input filtering during user registration.
- Brute-force rate limiting and lockout on 2FA challenge tokens and OTP verification.
- Enforced mandatory CSRF custom header checks (`X-Requested-With`, `X-CSRF-TOKEN`, `X-XSRF-TOKEN`, or `X-Client-Type`) for cookie-authenticated mutating requests.
