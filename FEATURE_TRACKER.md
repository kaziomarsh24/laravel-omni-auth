# Laravel OmniAuth — Feature Tracker & Module Roadmap

Status format:
- [x] Completed and verified with automated test suite
- [ ] Planned / Upcoming

---

## Module 1: Core Dual-Mode Engine & Security Base
1. [x] Modular opt-in feature flag architecture (`config/omni-auth.php` and `Features::*`).
2. [x] Intelligent client detection distinguishing Web (Cookies) from Mobile (Bearer) via headers and heuristics.
3. [x] Reverse-proxy aware secure cookie issuance (`HttpOnly`, `Secure`, `SameSite=Lax`) using `request()->isSecure()`.
4. [x] Dynamic credentials identifier resolution supporting `email`, `username`, or `phone`.
5. [x] Built-in brute-force protection with IP and identifier rate-limiting returning HTTP 429 and `retry_after`.
6. [x] Standard Laravel authentication event dispatching (`Login`, `Failed`, `Logout`).
7. [x] Unified Sanctum request token resolution hook via `Sanctum::getAccessTokenFromRequestUsing`.
8. [x] Unified authentication middleware (`omni.auth`) protecting web and mobile clients simultaneously.
9. [x] Single-use refresh token rotation mechanism revoking previous refresh tokens on renewal.
10. [x] Immediate browser cookie cleanup on failed refresh attempts to prevent client retry loops.
11. [x] Authenticated logout with access token revocation and cookie clearance.
12. [x] Database refresh token revocation during logout to eliminate lingering stored tokens.
13. [x] Multi-device global logout support (`Omni::logout(allDevices: true)`).
14. [x] Current user session inspection endpoint (`Omni::me()`).
15. [x] Conditional Spatie Laravel-Permission detection and automatic role/permission response hydration.

---

## Module 2: Zero-Boilerplate Registration & Auto-Hydration
16. [x] Registration method accepting FormRequest, Request, or raw array input (`Omni::register`).
17. [x] Mass-assignment security through automatic FormRequest validated dataset extraction.
18. [x] Dynamic auto-hydration supporting custom fields (`phone`, `company`, `address`) without code changes.
19. [x] Password hashing verification and automatic sanitization of confirmation fields.
20. [x] Default role assignment upon registration via configuration or runtime arguments.
21. [x] Standard Laravel registration event dispatching (`Registered`).
22. [x] Registration dual-mode delivery (HttpOnly cookies for Web, Bearer payload for Mobile).

---

## Module 3: API Resource & Ready-to-Use Routes
23. [x] Default `OmniUserResource` with `$this->when` conditional Spatie binding.
24. [x] Configurable user resource override option (`config('omni-auth.user_resource')`).
25. [x] Opt-in ready-to-use API route definitions (`/api/auth/login`, `/register`, `/refresh`, `/logout`, `/me`).
26. [x] Built-in lightweight controller handling standard authentication flows with zero boilerplate.
27. [x] Replay attack detection revoking all active user sessions if an already-used refresh token is presented.

---

## Module 4: Multi-Device Management & FCM Token Lifecycle
28. [ ] Opt-in database migration for device session records (`auth_devices`).
29. [ ] Device fingerprinting extracting IP address, User-Agent, and client platform names.
30. [ ] Unified FCM push notification token storage mapped to individual client devices.
31. [ ] Automatic FCM token cleanup upon device logout to prevent unauthorized notification routing.
32. [ ] Active devices listing API (`Omni::devices()->all()`).
33. [ ] Remote single-device session revocation endpoint (`Omni::devices()->revoke($id)`).
34. [ ] Revocation of all other active sessions while preserving current device session (`logoutOthers`).

---

## Module 5: Two-Factor Authentication (TOTP & Recovery Codes)
35. [ ] Opt-in database migration for two-factor credentials (`auth_two_factor`).
36. [ ] Cryptographic TOTP secret generator and QR code URI generation for authenticator apps.
37. [ ] Pre-authentication challenge flow returning temporary session tokens (`requires_2fa`).
38. [ ] TOTP 6-digit code verification endpoint exchanging temporary token for final tokens.
39. [ ] Hashed emergency one-time recovery codes generation and verification.
40. [ ] Fallback one-time passcode (OTP) delivery via email or SMS when authenticator is inaccessible.

---

## Module 6: Social Authentication & Mobile Native Token Exchange
41. [ ] Opt-in database migration for linked social providers (`auth_social_accounts`).
42. [ ] Web OAuth2 redirect and callback flow handling for Google, Apple, and GitHub.
43. [ ] Mobile native token exchange endpoint (`/api/auth/social/exchange` for Google/Apple ID tokens).
44. [ ] Sign In with Apple client secret generation and private relay email decryption.
45. [ ] Intelligent account linking merging verified social logins into existing user accounts.

---

## Module 7: Verification, Account Management & Passwordless Authentication
46. [ ] Cryptographic time-limited OTP generation for password reset requests.
47. [ ] Temporary signed password reset token issuance and validation.
48. [ ] Global session revocation terminating all existing sessions upon password change.
49. [ ] Password strength validation enforcing entropy and blocking breached or common passwords.
50. [ ] Standard `MustVerifyEmail` support with verification status check and resend verification endpoint.
51. [ ] App Store mandatory account deletion & GDPR compliance (`Omni::deleteAccount()` with token/FCM cleanup).
52. [ ] Passwordless magic login link generation with cryptographic signed URLs.
53. [ ] Mobile application deep-link support for magic link authentication flows.
54. [ ] Anti-abuse rate-limiting and lockout for OTP and magic link dispatching.

---

## Module 8: Documentation & Developer Experience
55. [ ] Astro Starlight documentation portal located in `/docs`.
56. [ ] Interactive multi-client tabbed guides comparing Next.js Web versus Flutter Mobile implementations.
57. [ ] Artisan publishing commands for configuration, migrations, and routes.
