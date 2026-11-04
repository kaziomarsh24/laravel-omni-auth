---
title: Token Rotation & Device Tracking
description: Sliding refresh token rotation, device auditing, and session revocation mechanics.
---

To maintain high security without forcing users to re-enter passwords daily, OmniAuth implements sliding token rotation paired with device session tracking.

---

## Token Rotation Mechanics

When a client receives tokens, two distinct token records are generated in Laravel Sanctum:

1. **Access Token**: Short-lived (default 15 minutes) with full API abilities `['access-api']`.
2. **Refresh Token**: Long-lived (default 30 days) with restricted ability `['refresh']`.

```text
Time 0:00                Time 0:14              Time 0:15
+--------------------+   Access token valid     +-----------------------------+
| Client Logs In     |   -------------------->  | Access Token Expires (401)  |
+--------------------+                          +-----------------------------+
   Issues:                                                     |
   - Access Token A (15m)                                      v
   - Refresh Token R1 (30d)                     +-----------------------------+
                                                | POST /api/auth/refresh      |
                                                | with Refresh Token R1       |
                                                +-----------------------------+
                                                               |
                                                +--------------+--------------+
                                                | Revokes Token R1            |
                                                | Issues:                     |
                                                | - Access Token B (15m)      |
                                                | - Refresh Token R2 (30d)    |
                                                +-----------------------------+
```

### Single-Use Refresh Tokens
Refresh tokens are strictly single-use. When `/api/auth/refresh` is called:
- OmniAuth validates the provided refresh token.
- The existing refresh token is immediately deleted from the database.
- A new access token and a new sliding refresh token are generated.
- If a revoked refresh token is presented again, the request fails with HTTP 401.

---

## Device Session Linkage

Every authenticated session is tracked in the `auth_devices` database table:

| Column | Description |
| :--- | :--- |
| `id` | Unique primary key for the device session |
| `user_id` | Foreign key referencing the authenticated user |
| `device_id` | Unique client-provided hardware or installation UUID |
| `platform` | Operating system (`ios`, `android`, `web`, `windows`, `macos`) |
| `device_name` | Human-readable label (e.g., "iPhone 15 Pro", "Chrome on macOS") |
| `browser` | Detected browser engine or app bundle |
| `ip_address` | Client IP address at time of authentication |
| `fcm_token` | Optional Firebase Cloud Messaging push token for push notifications |
| `refresh_token_id` | Foreign key linking this device to its active refresh token |
| `last_active_at` | Timestamp of the most recent API activity |

### Device Revocation

When a user views their active sessions via `GET /api/auth/devices`, they can revoke any device by ID (`DELETE /api/auth/devices/{id}`):

```php
// Inside DeviceManager::revoke()
$device = AuthDevice::where('user_id', $user->id)->findOrFail($deviceId);

// Delete the bound refresh token immediately
if ($device->refresh_token_id) {
    PersonalAccessToken::where('id', $device->refresh_token_id)->delete();
}

// Delete all personal access tokens associated with this device
// ...
$device->delete();
```

Because the refresh token record is deleted in the database, any future attempt by that device to refresh its session receives an immediate HTTP 401 error, terminating the compromised session.

---

## Automated Pruning Command

To prevent database bloat from expired Sanctum tokens and abandoned device records, OmniAuth provides the `omni:prune-tokens` Artisan command:

```bash
php artisan omni:prune-tokens --days=30
```

This command executes two cleanup tasks:
1. Deletes all `personal_access_tokens` whose `expires_at` timestamp has passed.
2. Deletes all `auth_devices` records that have been inactive (`last_active_at`) for more than the specified number of days (default: 30 days).
