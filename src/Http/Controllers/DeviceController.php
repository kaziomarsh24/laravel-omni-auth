<?php

namespace KaziOmar\OmniAuth\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use KaziOmar\OmniAuth\Facades\Omni;
use KaziOmar\OmniAuth\Features;

class DeviceController extends Controller
{
    /**
     * Ensure device tracking feature is enabled.
     */
    protected function ensureFeatureEnabled(): ?JsonResponse
    {
        if (!Features::enabled(Features::deviceTracking())) {
            return response()->json([
                'ok' => false,
                'message' => 'Device tracking feature is disabled.',
            ], 403);
        }

        return null;
    }

    /**
     * List all active logged-in devices for the authenticated user.
     */
    public function index(Request $request): JsonResponse
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        $devices = Omni::devices()->all($request->user(), $request);

        return response()->json([
            'ok' => true,
            'data' => [
                'devices' => $devices,
            ],
        ]);
    }

    /**
     * Revoke a specific device session and its access token.
     */
    public function destroy(Request $request, string|int $id): JsonResponse
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        $revoked = Omni::devices()->revoke($id, $request->user());

        if (!$revoked) {
            return response()->json([
                'ok' => false,
                'message' => 'Device session not found or already revoked.',
            ], 404);
        }

        return response()->json([
            'ok' => true,
            'message' => 'Device session successfully revoked.',
        ]);
    }

    /**
     * Terminate all other active device sessions except the current one.
     */
    public function logoutOthers(Request $request): JsonResponse
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        $count = Omni::devices()->logoutOthers($request->user(), $request);

        return response()->json([
            'ok' => true,
            'message' => "Successfully terminated {$count} other device sessions.",
            'data' => [
                'revoked_count' => $count,
            ],
        ]);
    }

    /**
     * Update the push notification token (FCM / Expo / OneSignal) for the current device session.
     */
    public function updateFcm(Request $request): JsonResponse
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        $pushToken = $request->input('push_token')
            ?? $request->input('fcm_token')
            ?? $request->header('X-Push-Token')
            ?? $request->header('X-FCM-Token');

        if (!$pushToken || !is_string($pushToken)) {
            return response()->json([
                'ok' => false,
                'message' => 'The push_token or fcm_token field is required.',
            ], 422);
        }

        $device = Omni::devices()->updateFcmToken(
            $pushToken,
            $request->user(),
            $request
        );

        return response()->json([
            'ok' => true,
            'message' => 'FCM token updated successfully.',
            'data' => [
                'device' => $device,
            ],
        ]);
    }
}
