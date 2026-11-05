---
title: Overview
description: Introduction to Laravel OmniAuth and its system design principles.
---

Laravel OmniAuth is a comprehensive, production-grade authentication package designed for engineering teams running Laravel as an API backend serving both web single-page applications (SPAs) and native mobile applications (iOS and Android).

While Laravel provides fundamental primitives such as Sanctum and Socialite, assembling them into a hardened, production-ready system requires hundreds of lines of boilerplate and careful security auditing. Most engineering teams repeatedly solve the same challenges: dual client token semantics, device revocation, two-factor authentication, social token exchange, and account lifecycle management.

OmniAuth provides a unified, battle-tested API surface consisting of 29 production-ready endpoints and an extensible service architecture.

## Supported Environments

- **PHP**: 8.2, 8.3, 8.4, 8.5, 8.6
- **Laravel**: 11.x, 12.x, 13.x
- **Databases**: MySQL 8.0+, PostgreSQL 13+, SQLite 3.35+
- **Cache Drivers**: Redis, Memcached, Database, Array (testing)

## Functional Domains

The package organizes authentication responsibilities into seven distinct, decoupled modules:

### 1. Core Authentication
Handles registration, credential-based login, token renewal, session termination, and profile retrieval. Supports dual-mode delivery: SameSite HttpOnly cookies for web browsers and short-lived Bearer tokens for mobile clients.
- Learn more: [Dual-Mode Architecture](/laravel-omni-auth/architecture/dual-mode-tokens/) | [Core API Reference](/laravel-omni-auth/reference/api-reference/#1-core-authentication)

### 2. Device Management
Every authenticated session is anchored to a tracked device record storing IP address, platform (iOS, Android, Web, Desktop), browser or app version, and optional push notification tokens (FCM/APNS). Users can list active sessions and revoke compromised devices.
- Learn more: [Device Management Guide](/laravel-omni-auth/features/device-management/) | [Device API Reference](/laravel-omni-auth/reference/api-reference/#2-multi-device-management)

### 3. Two-Factor Authentication (TOTP)
RFC 6238 compliant time-based one-time passwords. Secrets are encrypted at rest with Laravel's application key. Recovery codes are securely hashed using Laravel's configured hasher (`Hash::make`, Bcrypt/Argon2id). Setup and recovery code regeneration require password re-authentication.
- Learn more: [Two-Factor Authentication Guide](/laravel-omni-auth/features/two-factor-auth/) | [2FA API Reference](/laravel-omni-auth/reference/api-reference/#3-two-factor-authentication)

### 4. Social Authentication
Unified social login covering standard OAuth 2.0 browser redirect flows and native mobile ID token exchange (Google and Apple). Includes cryptographic RS256 signature verification via Apple JWKS with safe cache fallback.
- Learn more: [Social Login Guide](/laravel-omni-auth/features/social-login/) | [Social API Reference](/laravel-omni-auth/reference/api-reference/#4-social-authentication--token-exchange)

### 5. Password Management
Secure password reset flows via signed URL or 6-digit OTP codes. Open-redirect protected redirect validation rejects host-spoofing techniques.
- Learn more: [Security Defenses](/laravel-omni-auth/architecture/security-defenses/) | [Password API Reference](/laravel-omni-auth/reference/api-reference/#5-password-reset--otp-verification)

### 6. Passwordless Magic Links
Cryptographically signed, single-use authentication links sent via email. Enforces expiration and client-type isolation.
- Learn more: [Passwordless Magic Links Guide](/laravel-omni-auth/features/magic-links/) | [Magic Links API Reference](/laravel-omni-auth/reference/api-reference/#6-passwordless-magic-links)

### 7. Verification and Account Lifecycle
Signed email verification flows, self-service account deletion with cascading credential cleanup, and unverified account purge capabilities.
- Learn more: [Verification & Account Deletion Guide](/laravel-omni-auth/features/verification-and-deletion/) | [Lifecycle API Reference](/laravel-omni-auth/reference/api-reference/#7-email-verification--lifecycle)

## Architecture at a Glance

The following diagram illustrates how OmniAuth handles requests across different client platforms:

```mermaid
graph TD
    subgraph Clients["Supported Client Platforms"]
        Web["🌐 Web SPA (Next.js / Vue / Nuxt)<br/>SameSite HttpOnly Cookies<br/>Custom Anti-CSRF Header"]
        Mobile["📱 Mobile App (Flutter / React Native / iOS / Android)<br/>Authorization: Bearer &lt;token&gt;<br/>X-Client-Type: mobile"]
    end

    subgraph Core["Laravel OmniAuth Core Engine"]
        Gateway["OmniAuth Dual-Mode Gateway"]
        Guard["Sanctum Token Guard & Scope Verifier"]
        Defense["Rate Limiting & Anti-Brute-Force Lockouts"]
    end

    subgraph Managers["Dedicated Service Managers"]
        M1["OmniAuthManager<br/>(Core Authentication & Token Rotation)"]
        M2["TwoFactorManager<br/>(RFC 6238 TOTP & Recovery Codes)"]
        M3["SocialAuthManager<br/>(OAuth 2.0 & Apple/Google Native JWKS)"]
        M4["DeviceManager<br/>(Multi-Device Tracking & Remote Revocation)"]
        M5["PasswordResetManager<br/>(Brute-Force Protected OTP Verification)"]
    end

    Web --> Gateway
    Mobile --> Gateway
    Gateway --> Guard
    Gateway --> Defense
    Guard --> Managers
```
