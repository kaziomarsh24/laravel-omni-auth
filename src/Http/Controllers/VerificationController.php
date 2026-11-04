<?php

namespace KaziOmar\OmniAuth\Http\Controllers;

use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use KaziOmar\OmniAuth\Facades\Omni;

class VerificationController extends Controller
{
    /**
     * Send email verification notification.
     */
    public function resendEmail(Request $request): JsonResponse
    {
        $user = $request->user();

        if (method_exists($user, 'hasVerifiedEmail') && $user->hasVerifiedEmail()) {
            return response()->json([
                'ok' => false,
                'message' => 'Email address is already verified.',
            ], 400);
        }

        Omni::passwordReset()->sendEmailVerification($user);

        return response()->json([
            'ok' => true,
            'message' => 'Email verification code has been dispatched.',
        ]);
    }

    /**
     * Verify email via code or URL hash.
     */
    public function verifyEmail(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'otp' => ['nullable', 'string'],
            'hash' => ['nullable', 'string'],
        ]);

        $verified = Omni::passwordReset()->verifyEmail(
            $request->user(),
            $validated['otp'] ?? null,
            $validated['hash'] ?? $request->route('hash')
        );

        if (!$verified) {
            return response()->json([
                'ok' => false,
                'message' => 'Invalid or expired verification code.',
            ], 422);
        }

        return response()->json([
            'ok' => true,
            'message' => 'Email address has been verified successfully.',
        ]);
    }

    /**
     * Request a passwordless magic login link.
     */
    public function sendMagicLink(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => ['required', 'email'],
            'redirect_url' => ['nullable', 'string'],
        ]);

        Omni::passwordReset()->sendMagicLink(
            $validated['email'],
            $validated['redirect_url'] ?? null
        );

        return response()->json([
            'ok' => true,
            'message' => 'If an account exists with this email, a login link has been dispatched.',
        ]);
    }

    /**
     * Verify magic login link or mobile code and log user in.
     */
    public function verifyMagicLink(Request $request): mixed
    {
        $validated = $request->validate([
            'token' => ['nullable', 'string'],
            'code' => ['nullable', 'string'],
            'email' => ['nullable', 'email'],
        ]);

        $tokenOrCode = $validated['token'] ?? $validated['code'] ?? $request->query('token');

        if (!$tokenOrCode) {
            return response()->json([
                'ok' => false,
                'message' => 'Authentication token or code is required.',
            ], 422);
        }

        $user = Omni::passwordReset()->verifyMagicToken(
            $tokenOrCode,
            $validated['email'] ?? null
        );

        if (!$user) {
            return response()->json([
                'ok' => false,
                'message' => 'Invalid or expired magic login link.',
            ], 401);
        }

        return Omni::respondWithDualModeTokens($user, $request, 'Logged in successfully via magic link.');
    }

    /**
     * Permanently delete user account and clean up all tokens and device sessions.
     */
    public function deleteAccount(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'password' => ['nullable', 'string'],
        ]);

        try {
            Omni::passwordReset()->deleteAccount(
                $request->user(),
                $validated['password'] ?? null
            );

            return response()->json([
                'ok' => true,
                'message' => 'Your account has been deleted permanently along with all active sessions.',
            ]);
        } catch (Exception $e) {
            return response()->json([
                'ok' => false,
                'message' => $e->getMessage(),
            ], 422);
        }
    }
}
