---
title: Device Management & Push Tokens
description: Multi-device session tracking, remote device revocation, and push notification tokens.
---

OmniAuth tracks every authenticated session as an active device record. Users can view every browser and mobile device logged into their account, inspect IP addresses and activity timestamps, and remotely log out suspicious sessions.

---

## Device Registration Lifecycle

Whenever an authentication event occurs (login, registration, social exchange, or magic link verification), OmniAuth extracts device details from the request:
- Client IP address (`request()->ip()`)
- Client platform (`ios`, `android`, `web`, `macos`, `windows`, `linux`)
- Browser or client application runtime
- Unique device identifier (`X-Device-Id` header or client-supplied UUID)
- Push notification token (optional Firebase Cloud Messaging token)

---

## Device Endpoints

### 1. List Active Devices

Retrieve all devices currently authenticated to the user's account:

```http
GET /api/auth/devices
Authorization: Bearer <access_token>
```

Response:
```json
{
  "status": "success",
  "data": [
    {
      "id": 1,
      "device_id": "iphone-uuid-1234",
      "device_name": "iPhone 15 Pro",
      "platform": "ios",
      "browser": "OmniApp/1.0.0",
      "ip_address": "192.168.1.50",
      "is_current": true,
      "last_active_at": "2026-11-04T12:00:00Z"
    },
    {
      "id": 2,
      "device_id": "chrome-mac-uuid",
      "device_name": "Chrome on macOS",
      "platform": "web",
      "browser": "Chrome 128.0",
      "ip_address": "203.0.113.10",
      "is_current": false,
      "last_active_at": "2026-11-03T18:30:00Z"
    }
  ]
}
```

The `is_current` boolean indicates whether that entry matches the token or device making the request.

---

### 2. Revoke a Specific Device

Revokes a remote device session by ID:

```http
DELETE /api/auth/devices/2
Authorization: Bearer <access_token>
```

Response:
```json
{
  "status": "success",
  "message": "Device session revoked successfully."
}
```

When a device is revoked:
1. Its tracked `auth_devices` record is deleted.
2. The bound sliding refresh token is permanently deleted from Sanctum storage.
3. If that remote device subsequently attempts to call `/api/auth/refresh`, it receives HTTP 401 and is forced to log in again.

---

### 3. Revoke All Other Devices

Logs out every session across all browsers and devices except the one currently making the request:

```http
DELETE /api/auth/devices/others
Authorization: Bearer <access_token>
```

Response:
```json
{
  "status": "success",
  "message": "All other device sessions have been revoked."
}
```

---

### 4. Update Push Notification Token (FCM / APNS)

Mobile clients can synchronize their device push tokens without re-authenticating:

```http
POST /api/auth/devices/fcm-token
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "fcm_token": "fcm_token_sample_abc123..."
}
```

Response:
```json
{
  "status": "success",
  "message": "Push notification token updated successfully."
}
```
