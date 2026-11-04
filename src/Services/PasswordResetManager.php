<?php

namespace KaziOmar\OmniAuth\Services;

use Exception;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Validation\Rules\Password;
use Illuminate\Validation\ValidationException;
use KaziOmar\OmniAuth\Events\AccountDeleted;
use KaziOmar\OmniAuth\Events\EmailVerificationRequested;
use KaziOmar\OmniAuth\Events\MagicLinkRequested;
use KaziOmar\OmniAuth\Events\PasswordResetOtpRequested;
use KaziOmar\OmniAuth\Models\AuthDevice;
use KaziOmar\OmniAuth\Models\AuthSocialAccount;
use KaziOmar\OmniAuth\Models\AuthTwoFactor;

class PasswordResetManager
{
    public function __construct(
        protected DeviceManager $deviceManager
    ) {}

    /**
     * Get the cache repository.
     */
    protected function cache(): CacheRepository
    {
        $store = config('omni-auth.cache_store');

        return $store ? Cache::store($store) : Cache::store();
    }

    /**
     * Send a password reset OTP and signed URL to the requested email address.
     * Always returns true to prevent user enumeration vulnerabilities.
     */
    public function sendResetOtp(string $email, ?string $redirectUrl = null): bool
    {
        $throttleKey = "omni_pwd_reset_dispatch_{$email}";
        if (RateLimiter::tooManyAttempts($throttleKey, 5)) {
            $seconds = RateLimiter::availableIn($throttleKey);
            throw ValidationException::withMessages([
                'email' => ["Too many password reset requests. Please wait {$seconds} seconds."],
            ]);
        }
        RateLimiter::hit($throttleKey, 60);

        $userModelClass = config('omni-auth.user_model', 'App\\Models\\User');
        /** @var (Authenticatable&Model)|null $user */
        $user = $userModelClass::where('email', $email)->first();

        if (!$user) {
            return true; // Prevent timing / enumeration attacks
        }

        // Generate 6-digit numeric OTP
        $otp = (string) random_int(100000, 999999);
        $ttl = (int) config('omni-auth.password_reset.otp_ttl', 15);

        $otpKey = "omni_pwd_reset_otp_{$email}";
        $attemptsKey = "omni_pwd_reset_attempts_{$email}";

        $this->cache()->put($otpKey, Hash::make($otp), now()->addMinutes($ttl));
        $this->cache()->put($attemptsKey, 0, now()->addMinutes($ttl));

        // Generate temporary signed URL if applicable
        $signedUrl = null;
        if (Route::has('omni.password.reset.url')) {
            $signedUrl = URL::temporarySignedRoute(
                'omni.password.reset.url',
                now()->addMinutes($ttl),
                ['email' => $email]
            );
        } elseif ($redirectUrl) {
            $signedUrl = $redirectUrl . (str_contains($redirectUrl, '?') ? '&' : '?') . http_build_query([
                'email' => $email,
            ]);
        }

        event(new PasswordResetOtpRequested($user, $otp, $signedUrl));

        return true;
    }

    /**
     * Verify a password reset OTP and return a temporary single-use reset token.
     */
    public function verifyResetOtp(string $email, string $otp): ?string
    {
        $otpKey = "omni_pwd_reset_otp_{$email}";
        $attemptsKey = "omni_pwd_reset_attempts_{$email}";

        $hashedOtp = $this->cache()->get($otpKey);
        $attempts = (int) $this->cache()->get($attemptsKey, 0);
        $maxAttempts = (int) config('omni-auth.password_reset.max_attempts', 5);

        if (!$hashedOtp) {
            return null;
        }

        if ($attempts >= $maxAttempts) {
            $this->cache()->forget($otpKey);
            $this->cache()->forget($attemptsKey);
            throw ValidationException::withMessages([
                'otp' => ['Too many failed reset attempts. Please request a new passcode.'],
            ]);
        }

        if (!Hash::check(trim($otp), $hashedOtp)) {
            $this->cache()->increment($attemptsKey);
            return null;
        }

        // Clear OTP immediately (single-use)
        $this->cache()->forget($otpKey);
        $this->cache()->forget($attemptsKey);

        $userModelClass = config('omni-auth.user_model', 'App\\Models\\User');
        /** @var (Authenticatable&Model)|null $user */
        $user = $userModelClass::where('email', $email)->first();

        if (!$user) {
            return null;
        }

        // Issue temporary reset token valid for 15 minutes
        $resetToken = 'pwd_reset_' . Str::random(48);
        $tokenTtl = (int) config('omni-auth.password_reset.token_ttl', 15);

        $this->cache()->put(
            "omni_pwd_reset_token_{$resetToken}",
            $user->getAuthIdentifier(),
            now()->addMinutes($tokenTtl)
        );

        return $resetToken;
    }

    /**
     * Reset the user password using a verified reset token.
     * Enforces password strength and executes global session revocation.
     */
    public function resetPassword(string $resetToken, string $newPassword): bool
    {
        $tokenKey = "omni_pwd_reset_token_{$resetToken}";
        $userId = $this->cache()->get($tokenKey);

        if (!$userId) {
            throw ValidationException::withMessages([
                'token' => ['Invalid or expired password reset token.'],
            ]);
        }

        $this->validatePasswordStrength($newPassword);

        $userModelClass = config('omni-auth.user_model', 'App\\Models\\User');
        /** @var (Authenticatable&Model)|null $user */
        $user = $userModelClass::find($userId);

        if (!$user) {
            $this->cache()->forget($tokenKey);
            return false;
        }

        // Update password
        $user->password = Hash::make($newPassword);
        $user->save();

        // Invalidate reset token immediately
        $this->cache()->forget($tokenKey);

        // Global Session Revocation: terminate all existing tokens across all devices
        if (method_exists($user, 'tokens')) {
            $user->tokens()->delete();
        }

        AuthDevice::where('user_id', $user->getAuthIdentifier())->delete();

        event(new \Illuminate\Auth\Events\PasswordReset($user));

        return true;
    }

    /**
     * Enforce password entropy and complexity requirements.
     */
    public function validatePasswordStrength(string $password): void
    {
        $enforce = config('omni-auth.password_reset.enforce_strength', true);

        if (!$enforce) {
            if (strlen($password) < 8) {
                throw ValidationException::withMessages([
                    'password' => ['The password must be at least 8 characters.'],
                ]);
            }
            return;
        }

        $validator = Validator::make(['password' => $password], [
            'password' => [
                'required',
                'string',
                Password::min(8)
                    ->letters()
                    ->mixedCase()
                    ->numbers()
                    ->symbols()
                    ->uncompromised(),
            ],
        ]);

        if ($validator->fails()) {
            throw new ValidationException($validator);
        }
    }

    /**
     * Send email verification notification with signed URL and OTP.
     */
    public function sendEmailVerification(Authenticatable|Model $user): bool
    {
        if (method_exists($user, 'hasVerifiedEmail') && $user->hasVerifiedEmail()) {
            return false;
        }

        $ttl = (int) config('omni-auth.verification.ttl', 60);
        $otp = (string) random_int(100000, 999999);

        $otpKey = "omni_email_verify_otp_{$user->getAuthIdentifier()}";
        $this->cache()->put($otpKey, Hash::make($otp), now()->addMinutes($ttl));

        $email = method_exists($user, 'getEmailForVerification') ? $user->getEmailForVerification() : $user->email;
        $hash = sha1($email);

        $signedUrl = URL::temporarySignedRoute(
            'omni.email.verify',
            now()->addMinutes($ttl),
            [
                'id' => $user->getAuthIdentifier(),
                'hash' => $hash,
            ]
        );

        event(new EmailVerificationRequested($user, $signedUrl, $otp));

        return true;
    }

    /**
     * Verify email via code or URL hash.
     */
    public function verifyEmail(Authenticatable|Model $user, ?string $otp = null, ?string $hash = null): bool
    {
        if (method_exists($user, 'hasVerifiedEmail') && $user->hasVerifiedEmail()) {
            return true;
        }

        $email = method_exists($user, 'getEmailForVerification') ? $user->getEmailForVerification() : $user->email;

        // 1. Verify via numeric OTP if provided
        if ($otp) {
            $otpKey = "omni_email_verify_otp_{$user->getAuthIdentifier()}";
            $hashedOtp = $this->cache()->get($otpKey);

            if (!$hashedOtp || !Hash::check(trim($otp), $hashedOtp)) {
                return false;
            }

            $this->cache()->forget($otpKey);
        } elseif ($hash) {
            // 2. Verify via URL SHA1 hash
            if (!hash_equals((string) $hash, sha1($email))) {
                return false;
            }
        } else {
            return false;
        }

        if (method_exists($user, 'markEmailAsVerified')) {
            $user->markEmailAsVerified();
        } else {
            $user->email_verified_at = now();
            $user->save();
        }

        event(new \Illuminate\Auth\Events\Verified($user));

        return true;
    }

    /**
     * Send passwordless magic login link and 6-digit code.
     */
    public function sendMagicLink(string $email, ?string $redirectUrl = null): bool
    {
        $throttleKey = "omni_magic_dispatch_{$email}";
        if (RateLimiter::tooManyAttempts($throttleKey, 5)) {
            $seconds = RateLimiter::availableIn($throttleKey);
            throw ValidationException::withMessages([
                'email' => ["Too many magic link requests. Please wait {$seconds} seconds."],
            ]);
        }
        RateLimiter::hit($throttleKey, 60);

        $userModelClass = config('omni-auth.user_model', 'App\\Models\\User');
        /** @var (Authenticatable&Model)|null $user */
        $user = $userModelClass::where('email', $email)->first();

        if (!$user) {
            return true; // Prevent timing / enumeration attacks
        }

        $ttl = (int) config('omni-auth.magic_link.ttl', 15);
        $code = (string) random_int(100000, 999999);
        $token = 'magic_' . Str::random(48);

        $this->cache()->put("omni_magic_token_{$token}", $user->getAuthIdentifier(), now()->addMinutes($ttl));
        $this->cache()->put("omni_magic_code_{$email}", ['token' => $token, 'hash' => Hash::make($code)], now()->addMinutes($ttl));

        // Support mobile app deep-linking (e.g. myapp://auth/magic-link?token=...) or standard signed web URLs
        if ($redirectUrl) {
            $magicUrl = $redirectUrl . (str_contains($redirectUrl, '?') ? '&' : '?') . http_build_query([
                'token' => $token,
                'email' => $email,
            ]);
        } else {
            $magicUrl = URL::temporarySignedRoute(
                'omni.magic.verify',
                now()->addMinutes($ttl),
                ['token' => $token]
            );
        }

        event(new MagicLinkRequested($user, $magicUrl, $code));

        return true;
    }

    /**
     * Verify a magic link token or mobile numeric code and return the authenticated user.
     */
    public function verifyMagicToken(string $tokenOrCode, ?string $email = null): ?Authenticatable
    {
        $token = $tokenOrCode;

        // If numeric code provided with email, resolve underlying token
        if (preg_match('/^\d{6}$/', trim($tokenOrCode)) && $email) {
            $codeData = $this->cache()->get("omni_magic_code_{$email}");
            if (!$codeData || !Hash::check(trim($tokenOrCode), $codeData['hash'])) {
                return null;
            }
            $token = $codeData['token'];
            $this->cache()->forget("omni_magic_code_{$email}");
        }

        $tokenKey = "omni_magic_token_{$token}";
        $userId = $this->cache()->get($tokenKey);

        if (!$userId) {
            return null;
        }

        $this->cache()->forget($tokenKey);

        $userModelClass = config('omni-auth.user_model', 'App\\Models\\User');
        /** @var (Authenticatable&Model)|null $user */
        $user = $userModelClass::find($userId);

        if (!$user) {
            return null;
        }

        event(new \Illuminate\Auth\Events\Login(config('omni-auth.guard', 'sanctum'), $user, false));

        return $user;
    }

    /**
     * Delete user account permanently complying with Apple App Store Guideline 5.1.1(v) & GDPR.
     */
    public function deleteAccount(Authenticatable|Model $user, ?string $password = null): bool
    {
        // If account has password, verify confirmation password
        if (!empty($user->password)) {
            if (empty($password) || !Hash::check($password, $user->password)) {
                throw ValidationException::withMessages([
                    'password' => ['Incorrect password confirmation provided for account deletion.'],
                ]);
            }
        }

        $userId = $user->getAuthIdentifier();

        // 1. Revoke all personal access tokens
        if (method_exists($user, 'tokens')) {
            $user->tokens()->delete();
        }

        // 2. Clean up device sessions & FCM tokens
        AuthDevice::where('user_id', $userId)->delete();

        // 3. Clean up 2FA credentials
        AuthTwoFactor::where('user_id', $userId)->delete();

        // 4. Clean up linked social accounts
        AuthSocialAccount::where('user_id', $userId)->delete();

        // 5. Fire deletion event before record removal
        event(new AccountDeleted($user));

        // 6. Delete user record
        return (bool) $user->delete();
    }
}
