<?php

namespace KaziOmar\OmniAuth\Http\Controllers;

use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use KaziOmar\OmniAuth\Facades\Omni;
use KaziOmar\OmniAuth\Features;

class PasswordResetController extends Controller
{
    /**
     * Ensure password reset feature is enabled.
     */
    protected function ensureFeatureEnabled(): ?JsonResponse
    {
        if (!Features::enabled(Features::passwordReset())) {
            return response()->json([
                'ok' => false,
                'message' => 'Password reset feature is disabled.',
            ], 403);
        }

        return null;
    }

    /**
     * Request a password reset OTP or link.
     */
    public function forgotPassword(Request $request): JsonResponse
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        $validated = $request->validate([
            'email' => ['required', 'email'],
            'redirect_url' => ['nullable', 'string'],
        ]);

        Omni::passwordReset()->sendResetOtp(
            $validated['email'],
            $validated['redirect_url'] ?? null
        );

        return response()->json([
            'ok' => true,
            'message' => 'If an account exists for this email, a verification code has been sent.',
        ]);
    }

    /**
     * Verify the 6-digit numeric OTP and exchange it for a temporary reset token.
     */
    public function verifyOtp(Request $request): JsonResponse
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        $validated = $request->validate([
            'email' => ['required', 'email'],
            'otp' => ['required', 'string'],
        ]);

        try {
            $resetToken = Omni::passwordReset()->verifyResetOtp(
                $validated['email'],
                $validated['otp']
            );

            if (!$resetToken) {
                return response()->json([
                    'ok' => false,
                    'message' => 'Invalid or expired verification code.',
                ], 422);
            }

            return response()->json([
                'ok' => true,
                'message' => 'Code verified successfully.',
                'data' => [
                    'reset_token' => $resetToken,
                ],
            ]);
        } catch (Exception $e) {
            return response()->json([
                'ok' => false,
                'message' => $e->getMessage(),
            ], 422);
        }
    }

    /**
     * Reset password using temporary reset token and enforce global session revocation.
     */
    public function resetPassword(Request $request): JsonResponse
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        $validated = $request->validate([
            'token' => ['required', 'string'],
            'password' => ['required', 'string', 'confirmed'],
        ]);

        try {
            Omni::passwordReset()->resetPassword(
                $validated['token'],
                $validated['password']
            );

            return response()->json([
                'ok' => true,
                'message' => 'Your password has been reset successfully. All active sessions have been terminated.',
            ]);
        } catch (Exception $e) {
            return response()->json([
                'ok' => false,
                'message' => $e->getMessage(),
            ], 422);
        }
    }
}
