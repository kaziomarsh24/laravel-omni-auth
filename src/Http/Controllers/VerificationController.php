<?php

namespace KaziOmar\OmniAuth\Http\Controllers;

use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Validation\ValidationException;
use KaziOmar\OmniAuth\Facades\Omni;
use KaziOmar\OmniAuth\Features;

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
     * C5: Supports both authenticated API verification and direct signed browser URL clicks.
     */
    public function verifyEmail(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'otp' => ['nullable', 'string'],
            'hash' => ['nullable', 'string'],
        ]);

        $user = $request->user();

        // If clicking email link in a browser, resolve user from signed route ID
        if ($request->route('id')) {
            if (!$request->hasValidSignature()) {
                return response()->json([
                    'ok' => false,
                    'message' => 'Invalid, expired, or tampered verification link or code.',
                ], 422);
            }

            $userModelClass = config('omni-auth.user_model', 'App\\Models\\User');
            $user = $userModelClass::find($request->route('id'));

            if (!$user) {
                return response()->json([
                    'ok' => false,
                    'message' => 'Invalid, expired, or tampered verification link or code.',
                ], 422);
            }
        }

        if (!$user) {
            return response()->json([
                'ok' => false,
                'message' => 'Unauthenticated.',
            ], 401);
        }

        $verified = Omni::passwordReset()->verifyEmail(
            $user,
            $validated['otp'] ?? null,
            $validated['hash'] ?? $request->route('hash'),
            $request
        );

        if (!$verified) {
            return response()->json([
                'ok' => false,
                'message' => 'Invalid, expired, or tampered verification link or code.',
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
        if (!Features::enabled(Features::magicLoginLink())) {
            return response()->json([
                'ok' => false,
                'message' => 'Magic login link feature is disabled.',
            ], 403);
        }

        $validated = $request->validate([
            'email' => ['required', 'email'],
            'redirect_url' => ['nullable', 'string'],
        ]);

        try {
            Omni::passwordReset()->sendMagicLink(
                $validated['email'],
                $validated['redirect_url'] ?? null
            );

            return response()->json([
                'ok' => true,
                'message' => 'If an account exists with this email, a login link has been dispatched.',
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'ok' => false,
                'message' => $e->getMessage(),
                'errors' => $e->errors(),
            ], 422);
        }
    }

    /**
     * Verify magic login link or mobile code and log user in.
     */
    public function verifyMagicLink(Request $request): mixed
    {
        if (!Features::enabled(Features::magicLoginLink())) {
            return response()->json([
                'ok' => false,
                'message' => 'Magic login link feature is disabled.',
            ], 403);
        }

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

        try {
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

            // C3: Enforce Two-Factor Authentication on Magic Link logins
            if (Features::enabled(Features::twoFactorAuth()) && Omni::twoFactor()->isEnabled($user)) {
                $challengeToken = Omni::twoFactor()->createChallengeToken($user);
                return response()->json([
                    'ok' => true,
                    'message' => 'Two-factor authentication required.',
                    'data' => [
                        'requires_2fa' => true,
                        'two_factor_token' => $challengeToken,
                    ],
                ], 200);
            }

            return Omni::respondWithDualModeTokens($user, $request, 'Logged in successfully via magic link.');
        } catch (ValidationException $e) {
            return response()->json([
                'ok' => false,
                'message' => $e->getMessage(),
                'errors' => $e->errors(),
            ], 422);
        }
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
        } catch (\Illuminate\Validation\ValidationException $e) {
            return response()->json([
                'ok' => false,
                'message' => $e->getMessage(),
                'errors' => $e->errors(),
            ], 422);
        } catch (Exception $e) {
            return response()->json([
                'ok' => false,
                'message' => $e->getMessage(),
            ], 422);
        }
    }
}
