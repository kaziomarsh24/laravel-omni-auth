<?php

namespace KaziOmar\OmniAuth\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use KaziOmar\OmniAuth\Facades\Omni;
use KaziOmar\OmniAuth\Features;

class TwoFactorController extends Controller
{
    /**
     * Ensure two-factor feature is enabled.
     */
    protected function ensureFeatureEnabled(): ?JsonResponse
    {
        if (!Features::enabled(Features::twoFactorAuth())) {
            return response()->json([
                'ok' => false,
                'message' => 'Two-factor authentication feature is disabled.',
            ], 403);
        }

        return null;
    }

    /**
     * Exchange a temporary pre-authentication challenge token + 2FA code for final tokens.
     */
    public function challenge(Request $request): JsonResponse
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        $request->validate([
            'two_factor_token' => 'required|string',
            'code' => 'required|string',
        ]);

        $user = Omni::twoFactor()->verifyChallenge(
            $request->input('two_factor_token'),
            $request->input('code')
        );

        if (!$user) {
            return response()->json([
                'ok' => false,
                'message' => 'Invalid or expired two-factor code.',
            ], 422);
        }

        return Omni::issueTokenResponse($user, $request, 'Two-factor authentication successful.');
    }

    /**
     * Set up two-factor authentication for the authenticated user.
     */
    public function setup(Request $request): JsonResponse
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        $setupData = Omni::twoFactor()->setup($request->user());

        return response()->json([
            'ok' => true,
            'message' => 'Two-factor setup initiated. Confirm with a valid code from your authenticator app to enable.',
            'data' => $setupData,
        ]);
    }

    /**
     * Confirm two-factor setup with a valid code from the authenticator app.
     */
    public function confirm(Request $request): JsonResponse
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        $request->validate([
            'code' => 'required|string',
        ]);

        $confirmed = Omni::twoFactor()->confirm($request->user(), $request->input('code'));

        if (!$confirmed) {
            return response()->json([
                'ok' => false,
                'message' => 'Invalid two-factor confirmation code.',
            ], 422);
        }

        return response()->json([
            'ok' => true,
            'message' => 'Two-factor authentication has been successfully enabled.',
        ]);
    }

    /**
     * Regenerate emergency backup recovery codes.
     */
    public function recoveryCodes(Request $request): JsonResponse
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        if (!Omni::twoFactor()->isEnabled($request->user())) {
            return response()->json([
                'ok' => false,
                'message' => 'Two-factor authentication is not active on this account.',
            ], 400);
        }

        $codes = Omni::twoFactor()->regenerateRecoveryCodes($request->user());

        return response()->json([
            'ok' => true,
            'message' => 'New recovery codes generated. Store them in a secure place.',
            'data' => [
                'recovery_codes' => $codes,
            ],
        ]);
    }

    /**
     * Disable two-factor authentication for the authenticated user.
     */
    public function disable(Request $request): JsonResponse
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        $disabled = Omni::twoFactor()->disable($request->user());

        return response()->json([
            'ok' => true,
            'message' => 'Two-factor authentication has been disabled.',
        ]);
    }

    /**
     * Request a fallback one-time passcode via event/notification when TOTP is inaccessible.
     */
    public function fallbackOtp(Request $request): JsonResponse
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        $request->validate([
            'two_factor_token' => 'required|string',
        ]);

        $sent = Omni::twoFactor()->sendFallbackOtp($request->input('two_factor_token'));

        if (!$sent) {
            return response()->json([
                'ok' => false,
                'message' => 'Invalid or expired two-factor challenge token.',
            ], 422);
        }

        return response()->json([
            'ok' => true,
            'message' => 'A fallback one-time passcode has been sent.',
        ]);
    }
}
