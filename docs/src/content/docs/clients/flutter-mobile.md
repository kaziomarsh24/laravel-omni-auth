---
title: Flutter Mobile Integration
description: Complete mobile client integration using Dio, Flutter Secure Storage, and native token exchange.
---

In native Flutter applications, tokens are stored securely in hardware-backed device storage (`Keychain` on iOS, `KeyStore` on Android) and transmitted via standard `Authorization: Bearer` headers.

---

## Required Dependencies

Add `dio` and `flutter_secure_storage` to your `pubspec.yaml`:

```yaml
dependencies:
  flutter:
    sdk: flutter
  dio: ^5.7.0
  flutter_secure_storage: ^9.2.2
```

---

## ApiClient Implementation with Token Refresh Interceptor

Create `lib/core/api_client.dart`:

```dart
import 'package:dio/dio.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class ApiClient {
  static const String baseUrl = 'https://api.example.com';
  final FlutterSecureStorage _storage = const FlutterSecureStorage();
  late final Dio dio;

  ApiClient() {
    dio = Dio(
      BaseOptions(
        baseUrl: baseUrl,
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-Client-Type': 'mobile',
        },
      ),
    );

    dio.interceptors.add(
      InterceptorsWrapper(
        onRequest: (options, handler) async {
          final accessToken = await _storage.read(key: 'access_token');
          if (accessToken != null && !options.headers.containsKey('Authorization')) {
            options.headers['Authorization'] = 'Bearer $accessToken';
          }
          return handler.next(options);
        },
        onError: (DioException error, handler) async {
          if (error.response?.statusCode == 401 &&
              !error.requestOptions.path.contains('/auth/login') &&
              !error.requestOptions.path.contains('/auth/refresh')) {
            final refreshed = await _attemptTokenRefresh();
            if (refreshed) {
              final newAccessToken = await _storage.read(key: 'access_token');
              error.requestOptions.headers['Authorization'] = 'Bearer $newAccessToken';
              final retryResponse = await dio.fetch(error.requestOptions);
              return handler.resolve(retryResponse);
            }
          }
          return handler.next(error);
        },
      ),
    );
  }

  Future<bool> _attemptTokenRefresh() async {
    final refreshToken = await _storage.read(key: 'refresh_token');
    if (refreshToken == null) return false;

    try {
      final response = await dio.post(
        '/api/auth/refresh',
        data: {'refresh_token': refreshToken},
        options: Options(headers: {'Authorization': 'Bearer $refreshToken'}),
      );

      final data = response.data['data'];
      final tokens = data['tokens'];

      await _storage.write(key: 'access_token', value: tokens['access_token']);
      await _storage.write(key: 'refresh_token', value: tokens['refresh_token']);
      return true;
    } catch (e) {
      // Refresh token expired or revoked; purge storage
      await _storage.deleteAll();
      return false;
    }
  }
}
```

---

## Native Google & Apple Sign-In Exchange

When using `google_sign_in` or `sign_in_with_apple` in Flutter:

```dart
Future<Map<String, dynamic>?> exchangeSocialToken({
  required String provider, // 'google' or 'apple'
  required String idToken,
}) async {
  final response = await dio.post(
    '/api/auth/social/exchange',
    data: {
      'provider': provider,
      'id_token': idToken,
    },
  );

  final data = response.data['data'];

  // Handle Two-Factor Challenge if active
  if (response.data['status'] == 'requires_2fa') {
    return {
      'requires_2fa': true,
      'challenge_token': data['challenge_token'],
    };
  }

  final tokens = data['tokens'];
  await _storage.write(key: 'access_token', value: tokens['access_token']);
  await _storage.write(key: 'refresh_token', value: tokens['refresh_token']);

  return {
    'requires_2fa': false,
    'user': data['user'],
  };
}
```
