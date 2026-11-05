---
title: Next.js & Web SPA Integration
description: Complete client-side integration guide for Next.js, React, and single-page applications.
---

When integrating web frontends with Laravel OmniAuth, the application should use `HttpOnly` cookies. Storing access tokens in browser memory or `localStorage` creates severe cross-site scripting (XSS) liabilities.

---

## Architecture Overview

- **Transport**: `credentials: 'include'` (Fetch) or `withCredentials: true` (Axios).
- **Storage**: Browser cookie jar manages `omni_access_token` and `omni_refresh_token` transparently.
- **CSRF Defense**: OmniAuth checks for custom headers on state-changing requests (`POST`, `PUT`, `DELETE`). Send `X-Requested-With: XMLHttpRequest` or the standard Laravel `X-XSRF-TOKEN`.

---

:::caution[CORS & HttpOnly Cookie Gotcha]
To enable web browsers to securely receive and persist `SameSite` HttpOnly cookies:

1. **Enable Credentials:** In your Laravel backend `config/cors.php`, you **must** set `'supports_credentials' => true`.
2. **Explicit Allowed Origins:** When `supports_credentials` is `true`, CORS specifications strictly prohibit wildcard origins (`'*'`). You must explicitly specify your frontend origin (e.g., `'allowed_origins' => ['http://localhost:3000', 'https://app.example.com']`).
3. **Axios `withCredentials`:** In Next.js, always set `withCredentials: true` on your HTTP client instance. Without this flag, browsers silently strip cookies from cross-origin requests.
:::

## Axios Setup Example

Create a reusable API client instance in `lib/api.ts`:

```typescript
import axios from 'axios';

export const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || 'https://api.example.com',
  withCredentials: true,
  headers: {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
  },
});

// Automatic Token Refresh Interceptor
let isRefreshing = false;
let failedQueue: Array<{
  resolve: (value?: unknown) => void;
  reject: (reason?: unknown) => void;
}> = [];

const processQueue = (error: unknown) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve();
    }
  });
  failedQueue = [];
};

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Intercept 401 Unauthorized errors (excluding auth endpoints)
    if (
      error.response?.status === 401 &&
      !originalRequest._retry &&
      !originalRequest.url?.includes('/api/auth/login') &&
      !originalRequest.url?.includes('/api/auth/refresh')
    ) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then(() => api(originalRequest));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        // Post to refresh endpoint; cookies are handled automatically
        await api.post('/api/auth/refresh');
        processQueue(null);
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError);
        // Force redirect to login on refresh failure
        if (typeof window !== 'undefined') {
          window.location.href = '/login';
        }
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);
```

---

## Login Flow Example

```typescript
import { api } from '@/lib/api';

export async function loginUser(email: string, password: string) {
  const response = await api.post('/api/auth/login', {
    email,
    password,
  });

  // If user has 2FA enabled:
  if (response.data.status === 'requires_2fa') {
    return {
      requires2FA: true,
      challengeToken: response.data.data.challenge_token,
    };
  }

  // Standard login successful; cookies are stored by the browser
  return {
    requires2FA: false,
    user: response.data.data.user,
  };
}
```

---

## Completing 2FA Challenge

```typescript
export async function verify2FA(challengeToken: string, code: string) {
  const response = await api.post('/api/auth/2fa/challenge', {
    challenge_token: challengeToken,
    code,
  });

  return response.data.data.user;
}
```

---

## Logout Flow

```typescript
export async function logoutUser() {
  await api.post('/api/auth/logout');
  if (typeof window !== 'undefined') {
    window.location.href = '/login';
  }
}
```
