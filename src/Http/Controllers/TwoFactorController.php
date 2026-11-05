<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Hash;
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

        // Support both two_factor_token and challenge_token for DX flexibility
        if (!$request->has('two_factor_token') && $request->has('challenge_token')) {
            $request->merge(['two_factor_token' => $request->input('challenge_token')]);
        }

        $request->validate([
            'two_factor_token' => 'required|string',
            'code' => 'required|string',
        ]);

        $token = $request->input('two_factor_token');
        $throttleKey = 'omni_2fa_challenge_attempts:' . hash('sha256', $token);
        $attempts = (int) Cache::get($throttleKey, 0);

        if ($attempts >= 5) {
            Cache::forget('omni_2fa_challenge:' . hash('sha256', $token));
            Cache::forget($throttleKey);

            return response()->json([
                'ok' => false,
                'message' => 'Too many invalid two-factor verification attempts. Challenge expired. Please log in again.',
            ], 422);
        }

        $user = Omni::twoFactor()->verifyChallenge(
            $token,
            $request->input('code')
        );

        if (!$user) {
            Cache::put($throttleKey, $attempts + 1, now()->addMinutes(10));

            return response()->json([
                'ok' => false,
                'message' => 'Invalid or expired two-factor code.',
            ], 422);
        }

        Cache::forget($throttleKey);
        \Illuminate\Support\Facades\RateLimiter::clear("omni_2fa_challenge_farming:{$user->getAuthIdentifier()}");

        event(new \Illuminate\Auth\Events\Login(config('omni-auth.guard', 'sanctum'), $user, false));

        return Omni::issueTokenResponse($user, $request, 'Two-factor authentication successful.');
    }

    /**
     * Set up two-factor authentication for the authenticated user.
     * C4: Requires re-authentication if 2FA is already active.
     */
    public function setup(Request $request): JsonResponse
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        $user = $request->user();
        $password = $request->input('password');
        $code = $request->input('code');

        $throttleKey = "omni_reauth_2fa_setup:{$user->getAuthIdentifier()}";
        if (\Illuminate\Support\Facades\RateLimiter::tooManyAttempts($throttleKey, 5)) {
            $seconds = \Illuminate\Support\Facades\RateLimiter::availableIn($throttleKey);
            return response()->json([
                'ok' => false,
                'message' => "Too many attempts. Please try again in {$seconds} seconds.",
                'retry_after' => $seconds,
            ], 429);
        }

        $hasPassword = Omni::hasUserSetPassword($user);

        // C4 / R2: Require re-authentication for initial setup
        if ($hasPassword) {
            if (!$password || !Hash::check($password, $user->password)) {
                \Illuminate\Support\Facades\RateLimiter::hit($throttleKey, 600);
                return response()->json([
                    'ok' => false,
                    'message' => 'Password confirmation is required to set up two-factor authentication.',
                ], 422);
            }
        } elseif ((bool) config('omni-auth.two_factor.reauth_passwordless', false)) {
            // R2: For passwordless (social-only) accounts, enforce email OTP verification if enabled
            $otp = $code ?? $request->input('otp');
            $otpKey = "omni_email_verify_otp_{$user->getAuthIdentifier()}";
            $hashedOtp = $this->cache()->get($otpKey);

            if (empty($otp)) {
                Omni::passwordReset()->sendEmailVerificationNotification($user);
                \Illuminate\Support\Facades\RateLimiter::hit($throttleKey, 600);
                return response()->json([
                    'ok' => false,
                    'message' => 'For passwordless accounts, a verification code has been dispatched to your email. Please provide the code to set up two-factor authentication.',
                    'requires_code' => true,
                ], 422);
            }

            if (!$hashedOtp || !Hash::check(trim((string) $otp), $hashedOtp)) {
                \Illuminate\Support\Facades\RateLimiter::hit($throttleKey, 600);
                return response()->json([
                    'ok' => false,
                    'message' => 'Invalid or expired email verification code provided.',
                ], 422);
            }

            $this->cache()->forget($otpKey);
        }

        // C4: If 2FA is already confirmed and active, require password or code re-auth
        if (Omni::twoFactor()->isEnabled($user)) {
            if ($hasPassword) {
                if (!$password || !Hash::check($password, $user->password)) {
                    \Illuminate\Support\Facades\RateLimiter::hit($throttleKey, 600);
                    return response()->json([
                        'ok' => false,
                        'message' => 'Current password confirmation is required to re-configure two-factor authentication.',
                    ], 422);
                }
            } elseif ($code) {
                $twoFactor = \KaziOmar\OmniAuth\Models\AuthTwoFactor::where('user_id', $user->getAuthIdentifier())->first();
                if (!$twoFactor || !Omni::twoFactor()->verifyCode($twoFactor->secret, trim($code))) {
                    \Illuminate\Support\Facades\RateLimiter::hit($throttleKey, 600);
                    return response()->json([
                        'ok' => false,
                        'message' => 'Valid two-factor code is required to re-configure two-factor authentication.',
                    ], 422);
                }
            } else {
                \Illuminate\Support\Facades\RateLimiter::hit($throttleKey, 600);
                return response()->json([
                    'ok' => false,
                    'message' => 'Authentication confirmation (password or two-factor code) is required.',
                ], 422);
            }
        }

        \Illuminate\Support\Facades\RateLimiter::clear($throttleKey);

        $setupData = Omni::twoFactor()->setup($user);

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

        $user = $request->user();

        if (!Omni::twoFactor()->isEnabled($user)) {
            return response()->json([
                'ok' => false,
                'message' => 'Two-factor authentication is not active on this account.',
            ], 400);
        }

        $throttleKey = "omni_reauth_2fa_recovery:{$user->getAuthIdentifier()}";
        if (\Illuminate\Support\Facades\RateLimiter::tooManyAttempts($throttleKey, 5)) {
            $seconds = \Illuminate\Support\Facades\RateLimiter::availableIn($throttleKey);
            return response()->json([
                'ok' => false,
                'message' => "Too many failed attempts. Please try again in {$seconds} seconds.",
                'retry_after' => $seconds,
            ], 429);
        }

        $password = $request->input('password');
        $code = $request->input('code');
        $hasPassword = Omni::hasUserSetPassword($user);

        if ($hasPassword) {
            if (!$password || !Hash::check($password, $user->password)) {
                \Illuminate\Support\Facades\RateLimiter::hit($throttleKey, 600);
                return response()->json([
                    'ok' => false,
                    'message' => 'Password confirmation is required to regenerate recovery codes.',
                ], 422);
            }
        } elseif ($code) {
            $twoFactor = \KaziOmar\OmniAuth\Models\AuthTwoFactor::where('user_id', $user->getAuthIdentifier())->first();
            if (!$twoFactor || !Omni::twoFactor()->verifyCode($twoFactor->secret, trim($code))) {
                \Illuminate\Support\Facades\RateLimiter::hit($throttleKey, 600);
                return response()->json([
                    'ok' => false,
                    'message' => 'Valid two-factor code is required to regenerate recovery codes.',
                ], 422);
            }
        } else {
            \Illuminate\Support\Facades\RateLimiter::hit($throttleKey, 600);
            return response()->json([
                'ok' => false,
                'message' => 'Authentication confirmation (password or two-factor code) is required.',
            ], 422);
        }

        \Illuminate\Support\Facades\RateLimiter::clear($throttleKey);

        $codes = Omni::twoFactor()->regenerateRecoveryCodes($user);

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
     * C4: Requires re-authentication (current password or TOTP code) with brute-force rate-limiting.
     */
    public function disable(Request $request): JsonResponse
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        $user = $request->user();
        $throttleKey = "omni_2fa_disable:{$user->getAuthIdentifier()}";

        if (\Illuminate\Support\Facades\RateLimiter::tooManyAttempts($throttleKey, 5)) {
            $seconds = \Illuminate\Support\Facades\RateLimiter::availableIn($throttleKey);
            return response()->json([
                'ok' => false,
                'message' => "Too many failed attempts. Please try again in {$seconds} seconds.",
                'retry_after' => $seconds,
            ], 429);
        }

        // C4: Re-authentication required to disable 2FA
        $password = $request->input('password');
        $code = $request->input('code');
        $hasPassword = Omni::hasUserSetPassword($user);

        if ($hasPassword) {
            if (!$password || !Hash::check($password, $user->password)) {
                \Illuminate\Support\Facades\RateLimiter::hit($throttleKey, 600);
                return response()->json([
                    'ok' => false,
                    'message' => 'Current password confirmation is required to disable two-factor authentication.',
                ], 422);
            }
        } elseif ($code) {
            $twoFactor = \KaziOmar\OmniAuth\Models\AuthTwoFactor::where('user_id', $user->getAuthIdentifier())->first();
            if (!$twoFactor || !Omni::twoFactor()->verifyCode($twoFactor->secret, trim($code))) {
                \Illuminate\Support\Facades\RateLimiter::hit($throttleKey, 600);
                return response()->json([
                    'ok' => false,
                    'message' => 'Valid two-factor code is required to disable two-factor authentication.',
                ], 422);
            }
        } else {
            \Illuminate\Support\Facades\RateLimiter::hit($throttleKey, 600);
            return response()->json([
                'ok' => false,
                'message' => 'Authentication confirmation (password or two-factor code) is required.',
            ], 422);
        }

        \Illuminate\Support\Facades\RateLimiter::clear($throttleKey);
        $disabled = Omni::twoFactor()->disable($user);

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

        if (!$request->has('two_factor_token') && $request->has('challenge_token')) {
            $request->merge(['two_factor_token' => $request->input('challenge_token')]);
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
