<?php

namespace KaziOmar\OmniAuth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use KaziOmar\OmniAuth\Models\AuthDevice;
use Laravel\Sanctum\PersonalAccessToken;

class DeviceManager
{
    /**
     * Record or update an active device session for an authenticated user.
     */
    public function track(
        Authenticatable|Model $user,
        ?Request $request = null,
        ?PersonalAccessToken $token = null,
        ?string $fcmToken = null,
        ?string $deviceName = null,
        ?PersonalAccessToken $refreshToken = null
    ): AuthDevice {
        $request = $request ?? request();

        $deviceId = $this->resolveDeviceId($user, $request);
        $resolvedDeviceName = $deviceName ?? $this->resolveDeviceName($request);
        $platform = $this->resolvePlatform($request);
        $resolvedFcmToken = $fcmToken
            ?? $request->header('X-Push-Token')
            ?? $request->header('X-FCM-Token')
            ?? $request->input('push_token')
            ?? $request->input('fcm_token');

        /** @var AuthDevice $device */
        $device = AuthDevice::where('user_id', $user->getAuthIdentifier())
            ->where('device_id', $deviceId)
            ->first();

        $attributes = [
            'token_id' => $token?->id ?? $device?->token_id,
            'refresh_token_id' => $refreshToken?->id ?? $device?->refresh_token_id,
            'device_name' => $resolvedDeviceName,
            'platform' => $platform,
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'last_active_at' => now(),
        ];

        if ($resolvedFcmToken !== null && trim($resolvedFcmToken) !== '') {
            $trimmedPushToken = trim($resolvedFcmToken);
            $attributes['fcm_token'] = $trimmedPushToken;

            // Device Handover / App Reinstall Safety:
            // If another user previously registered with this push token on the same physical device,
            // revoke it to prevent unauthorized cross-user push notifications.
            AuthDevice::where('fcm_token', $trimmedPushToken)
                ->where('user_id', '!=', $user->getAuthIdentifier())
                ->update(['fcm_token' => null]);
        }

        if ($device) {
            $device->update($attributes);
            return $device->fresh();
        }

        return AuthDevice::create(array_merge($attributes, [
            'user_id' => $user->getAuthIdentifier(),
            'device_id' => $deviceId,
        ]));
    }

    /**
     * Retrieve all active registered devices for the user with is_current_device flag.
     */
    public function all(?Authenticatable $user = null, ?Request $request = null): Collection
    {
        $user = $user ?? auth(config('omni-auth.guard', 'sanctum'))->user();

        if (!$user) {
            return collect();
        }

        $request = $request ?? request();
        $currentDevice = $this->current($user, $request);
        $currentDeviceId = $currentDevice?->id;

        return AuthDevice::where('user_id', $user->getAuthIdentifier())
            ->orderBy('last_active_at', 'desc')
            ->get()
            ->map(function (AuthDevice $device) use ($currentDeviceId) {
                $array = $device->toArray();
                $array['is_current_device'] = ($device->id === $currentDeviceId);

                return $array;
            });
    }

    /**
     * Retrieve the device record matching the current request session.
     */
    public function current(?Authenticatable $user = null, ?Request $request = null): ?AuthDevice
    {
        $user = $user ?? auth(config('omni-auth.guard', 'sanctum'))->user();

        if (!$user) {
            return null;
        }

        $request = $request ?? request();

        // 1. Check if authenticated Sanctum token matches
        if (method_exists($user, 'currentAccessToken') && $user->currentAccessToken()) {
            $accessToken = $user->currentAccessToken();
            if (isset($accessToken->id) && $accessToken->id !== null) {
                $device = AuthDevice::where('user_id', $user->getAuthIdentifier())
                    ->where('token_id', $accessToken->id)
                    ->first();

                if ($device) {
                    return $device;
                }
            }
        }

        // 2. Fall back to matching device_id
        $deviceId = $this->resolveDeviceId($user, $request);

        return AuthDevice::where('user_id', $user->getAuthIdentifier())
            ->where('device_id', $deviceId)
            ->first();
    }

    /**
     * Revoke a specific device session and its associated Sanctum access token.
     */
    public function revoke(int|string $id, ?Authenticatable $user = null): bool
    {
        $user = $user ?? auth(config('omni-auth.guard', 'sanctum'))->user();

        if (!$user) {
            return false;
        }

        $device = AuthDevice::where('user_id', $user->getAuthIdentifier())
            ->where(function ($query) use ($id) {
                $query->where('id', $id)->orWhere('device_id', $id);
            })
            ->first();

        if (!$device) {
            return false;
        }

        // Delete associated Sanctum access and refresh tokens if present
        if ($device->token_id) {
            PersonalAccessToken::where('id', $device->token_id)->delete();
        }
        if ($device->refresh_token_id) {
            PersonalAccessToken::where('id', $device->refresh_token_id)->delete();
        }

        return (bool) $device->delete();
    }

    /**
     * Revoke all other active device sessions for this user, keeping only the current device.
     */
    public function logoutOthers(?Authenticatable $user = null, ?Request $request = null): int
    {
        $user = $user ?? auth(config('omni-auth.guard', 'sanctum'))->user();

        if (!$user) {
            return 0;
        }

        $request = $request ?? request();
        $currentDevice = $this->current($user, $request);
        $currentId = $currentDevice?->id;
        $currentTokenId = $currentDevice?->token_id;

        $devicesToRevoke = AuthDevice::where('user_id', $user->getAuthIdentifier())
            ->when($currentId, fn($q) => $q->where('id', '!=', $currentId))
            ->get();

        $tokenIdsToDelete = $devicesToRevoke->pluck('token_id')
            ->merge($devicesToRevoke->pluck('refresh_token_id'))
            ->filter()
            ->values()
            ->all();

        if (!empty($tokenIdsToDelete)) {
            PersonalAccessToken::whereIn('id', $tokenIdsToDelete)->delete();
        }

        // Also clean up any loose tokens not attached to current device
        if (method_exists($user, 'tokens') && $currentTokenId) {
            $user->tokens()->where('id', '!=', $currentTokenId)->delete();
        }

        $count = $devicesToRevoke->count();
        AuthDevice::where('user_id', $user->getAuthIdentifier())
            ->when($currentId, fn($q) => $q->where('id', '!=', $currentId))
            ->delete();

        return $count;
    }

    /**
     * Cleanup FCM token and optionally device session upon user logout.
     */
    public function cleanupOnLogout(?Authenticatable $user = null, ?Request $request = null): void
    {
        $user = $user ?? auth(config('omni-auth.guard', 'sanctum'))->user();

        if (!$user) {
            return;
        }

        $request = $request ?? request();
        $device = $this->current($user, $request);

        if ($device) {
            // Purge FCM token to ensure no unauthorized push notifications reach this device
            $device->update(['fcm_token' => null]);
            $device->delete();
        }
    }

    /**
     * Update the FCM push notification token for the current active device.
     */
    public function updateFcmToken(string $fcmToken, ?Authenticatable $user = null, ?Request $request = null): ?AuthDevice
    {
        $user = $user ?? auth(config('omni-auth.guard', 'sanctum'))->user();

        if (!$user) {
            return null;
        }

        $request = $request ?? request();
        $device = $this->current($user, $request);

        if ($device) {
            $trimmed = trim($fcmToken);
            $device->update(['fcm_token' => $trimmed]);

            if ($trimmed !== '') {
                AuthDevice::where('fcm_token', $trimmed)
                    ->where('user_id', '!=', $user->getAuthIdentifier())
                    ->update(['fcm_token' => null]);
            }

            return $device->fresh();
        }

        // If no device record exists yet, track one now
        return $this->track($user, $request, null, $fcmToken);
    }

    /**
     * Resolve a unique device identifier from request headers or heuristics.
     */
    protected function resolveDeviceId(Authenticatable|Model $user, Request $request): string
    {
        $headerDeviceId = $request->header('X-Device-ID') ?? $request->input('device_id');

        if ($headerDeviceId && is_string($headerDeviceId)) {
            $trimmed = trim($headerDeviceId);
            if ($trimmed !== '' && strlen($trimmed) <= 128 && preg_match('/^[\w\-\.]{1,128}$/', $trimmed)) {
                return $trimmed;
            }
        }

        // Generate deterministic fingerprint from IP, User-Agent, and User ID
        $signature = implode('|', [
            $user->getAuthIdentifier(),
            $request->ip() ?? 'unknown-ip',
            $request->userAgent() ?? 'unknown-ua',
        ]);

        return 'dev_' . substr(hash('sha256', $signature), 0, 32);
    }

    /**
     * Resolve a human-friendly device name from header, payload, or User-Agent.
     */
    protected function resolveDeviceName(Request $request): string
    {
        $name = $request->header('X-Device-Name') ?? $request->input('device_name');

        if ($name && is_string($name) && trim($name) !== '') {
            return trim($name);
        }

        $ua = $request->userAgent() ?? '';

        if (str_contains($ua, 'iPhone')) {
            return 'Apple iPhone';
        }

        if (str_contains($ua, 'iPad')) {
            return 'Apple iPad';
        }

        if (str_contains($ua, 'Macintosh') || str_contains($ua, 'Mac OS X')) {
            return 'Mac (' . $this->detectBrowser($ua) . ')';
        }

        if (str_contains($ua, 'Windows')) {
            return 'Windows PC (' . $this->detectBrowser($ua) . ')';
        }

        if (str_contains($ua, 'Android')) {
            return 'Android Device';
        }

        if (str_contains($ua, 'Linux')) {
            return 'Linux (' . $this->detectBrowser($ua) . ')';
        }

        return 'Browser (' . $this->detectBrowser($ua) . ')';
    }

    /**
     * Detect client platform (web, android, ios, desktop).
     */
    protected function resolvePlatform(Request $request): string
    {
        $platform = $request->header('X-Client-Platform') ?? $request->input('platform');

        if ($platform && is_string($platform) && trim($platform) !== '') {
            return strtolower(trim($platform));
        }

        $clientType = strtolower((string) $request->header('X-Client-Type'));
        $ua = $request->userAgent() ?? '';

        if ($clientType === 'mobile' || str_contains($ua, 'Dart') || str_contains($ua, 'OkHttp')) {
            if (str_contains($ua, 'iPhone') || str_contains($ua, 'CFNetwork') || str_contains($ua, 'Darwin')) {
                return 'ios';
            }
            return 'android';
        }

        if (str_contains($ua, 'Android')) {
            return 'android';
        }

        if (str_contains($ua, 'iPhone') || str_contains($ua, 'iPad')) {
            return 'ios';
        }

        return 'web';
    }

    /**
     * Detect browser name from User-Agent string.
     */
    protected function detectBrowser(string $ua): string
    {
        if (str_contains($ua, 'Edg')) {
            return 'Edge';
        }
        if (str_contains($ua, 'Chrome')) {
            return 'Chrome';
        }
        if (str_contains($ua, 'Firefox')) {
            return 'Firefox';
        }
        if (str_contains($ua, 'Safari')) {
            return 'Safari';
        }
        if (str_contains($ua, 'Postman')) {
            return 'Postman';
        }

        return 'Web';
    }
}
