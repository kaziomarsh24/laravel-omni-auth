---
title: React Native & Expo Integration
description: Client integration for React Native and Expo using expo-secure-store.
---

For React Native and Expo applications, tokens are stored securely in the device's native keychain using `expo-secure-store` and submitted via the `Authorization: Bearer` header.

---

## Required Dependencies

```bash
npx expo install expo-secure-store
npm install axios
```

---

## API Client Setup

Create `src/services/api.ts`:

```typescript
import axios from 'axios';
import * as SecureStore from 'expo-secure-store';

const API_BASE_URL = 'https://api.example.com';

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'X-Client-Type': 'mobile',
  },
});

api.interceptors.request.use(async (config) => {
  const token = await SecureStore.getItemAsync('access_token');
  if (token && !config.headers.Authorization) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (
      error.response?.status === 401 &&
      !originalRequest._retry &&
      !originalRequest.url?.includes('/api/auth/login') &&
      !originalRequest.url?.includes('/api/auth/refresh')
    ) {
      originalRequest._retry = true;

      try {
        const refreshToken = await SecureStore.getItemAsync('refresh_token');
        if (!refreshToken) {
          throw new Error('No refresh token available');
        }

        const refreshResponse = await axios.post(
          `${API_BASE_URL}/api/auth/refresh`,
          { refresh_token: refreshToken },
          {
            headers: {
              'Accept': 'application/json',
              'Content-Type': 'application/json',
              'X-Client-Type': 'mobile',
              'Authorization': `Bearer ${refreshToken}`,
            },
          }
        );

        const { access_token, refresh_token: newRefreshToken } =
          refreshResponse.data.data.tokens;

        await SecureStore.setItemAsync('access_token', access_token);
        await SecureStore.setItemAsync('refresh_token', newRefreshToken);

        originalRequest.headers.Authorization = `Bearer ${access_token}`;
        return api(originalRequest);
      } catch (refreshErr) {
        await SecureStore.deleteItemAsync('access_token');
        await SecureStore.deleteItemAsync('refresh_token');
        return Promise.reject(refreshErr);
      }
    }

    return Promise.reject(error);
  }
);
```

---

## Native Device Registration

Pass your device ID and push token during login or after authentication:

```typescript
import * as Device from 'expo-device';
import * as Notifications from 'expo-notifications';

export async function syncPushToken() {
  const token = (await Notifications.getExpoPushTokenAsync()).data;
  await api.post('/api/auth/devices/fcm-token', {
    fcm_token: token,
  });
}
```
