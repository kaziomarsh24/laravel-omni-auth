<?php

namespace KaziOmar\OmniAuth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use KaziOmar\OmniAuth\Models\AuthTwoFactor;

class TwoFactorManager
{
    /**
     * Standard RFC 4648 Base32 alphabet.
     */
    protected const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Check if two-factor authentication is active and confirmed for a user.
     */
    public function isEnabled(Authenticatable|Model $user): bool
    {
        return AuthTwoFactor::where('user_id', $user->getAuthIdentifier())
            ->whereNotNull('confirmed_at')
            ->exists();
    }

    /**
     * Initiate two-factor setup for a user, generating a secret, recovery codes, and QR URI.
     *
     * @return array{secret: string, qr_code_uri: string, recovery_codes: array<string>}
     */
    public function setup(Authenticatable|Model $user): array
    {
        $secret = $this->generateSecret(32);
        $plainCodes = $this->generateRecoveryCodes(8);
        $hashedCodes = array_map(fn($code) => Hash::make($code), $plainCodes);

        $qrCodeUri = $this->qrCodeUri($secret, $user);

        AuthTwoFactor::updateOrCreate(
            ['user_id' => $user->getAuthIdentifier()],
            [
                'secret' => $secret,
                'recovery_codes' => $hashedCodes,
                'confirmed_at' => null, // Requires confirmation before being active
            ]
        );

        return [
            'secret' => $secret,
            'qr_code_uri' => $qrCodeUri,
            'recovery_codes' => $plainCodes,
        ];
    }

    /**
     * Confirm 2FA setup by validating a code from the authenticator app.
     */
    public function confirm(Authenticatable|Model $user, string $code): bool
    {
        /** @var AuthTwoFactor|null $twoFactor */
        $twoFactor = AuthTwoFactor::where('user_id', $user->getAuthIdentifier())->first();

        if (!$twoFactor || !$twoFactor->secret) {
            return false;
        }

        if ($this->verifyCode($twoFactor->secret, $code)) {
            $twoFactor->update(['confirmed_at' => now()]);
            return true;
        }

        return false;
    }

    /**
     * Disable two-factor authentication for a user.
     */
    public function disable(Authenticatable|Model $user): bool
    {
        return (bool) AuthTwoFactor::where('user_id', $user->getAuthIdentifier())->delete();
    }

    /**
     * Create a temporary pre-authentication challenge token for login flow.
     */
    public function createChallengeToken(Authenticatable|Model $user): string
    {
        $token = '2fa_tmp_' . Str::random(48);
        $ttlMinutes = (int) config('omni-auth.two_factor.challenge_ttl', 5);

        $this->cache()->put(
            $this->challengeCacheKey($token),
            $user->getAuthIdentifier(),
            now()->addMinutes($ttlMinutes)
        );

        return $token;
    }

    /**
     * Verify a 2FA challenge token with a TOTP code or an emergency recovery code.
     */
    public function verifyChallenge(string $challengeToken, string $codeOrRecovery): ?Authenticatable
    {
        $cacheKey = $this->challengeCacheKey($challengeToken);
        $userId = $this->cache()->get($cacheKey);

        if (!$userId) {
            return null;
        }

        $userModelClass = config('omni-auth.user_model', 'App\\Models\\User');
        /** @var (Authenticatable&Model)|null $user */
        $user = $userModelClass::find($userId);

        if (!$user) {
            $this->cache()->forget($cacheKey);
            return null;
        }

        /** @var AuthTwoFactor|null $twoFactor */
        $twoFactor = AuthTwoFactor::where('user_id', $user->getAuthIdentifier())
            ->whereNotNull('confirmed_at')
            ->first();

        if (!$twoFactor) {
            $this->cache()->forget($cacheKey);
            return null;
        }

        // 1. First, check if input is a valid 6-digit TOTP code
        if (preg_match('/^\d{6}$/', trim($codeOrRecovery))) {
            if ($this->verifyCode($twoFactor->secret, trim($codeOrRecovery))) {
                $this->cache()->forget($cacheKey);
                return $user;
            }
        }

        // 2. Otherwise, check if input matches any one-time backup recovery codes
        if ($this->verifyAndConsumeRecoveryCode($twoFactor, trim($codeOrRecovery))) {
            $this->cache()->forget($cacheKey);
            return $user;
        }

        // 3. Check fallback OTP if sent via email/SMS
        $fallbackKey = "omni_2fa_fallback_otp_{$userId}";
        $hashedOtp = $this->cache()->get($fallbackKey);
        if ($hashedOtp && Hash::check(trim($codeOrRecovery), $hashedOtp)) {
            $this->cache()->forget($fallbackKey);
            $this->cache()->forget($cacheKey);
            return $user;
        }

        return null;
    }

    /**
     * Send a fallback OTP to the user when authenticator is inaccessible.
     */
    public function sendFallbackOtp(string $challengeToken): bool
    {
        $cacheKey = $this->challengeCacheKey($challengeToken);
        $userId = $this->cache()->get($cacheKey);

        if (!$userId) {
            return false;
        }

        $userModelClass = config('omni-auth.user_model', 'App\\Models\\User');
        /** @var (Authenticatable&Model)|null $user */
        $user = $userModelClass::find($userId);

        if (!$user) {
            return false;
        }

        $otp = (string) random_int(100000, 999999);
        $otpCacheKey = "omni_2fa_fallback_otp_{$userId}";
        $ttl = (int) config('omni-auth.two_factor.fallback_otp_ttl', 5);

        $this->cache()->put($otpCacheKey, Hash::make($otp), now()->addMinutes($ttl));

        event(new \KaziOmar\OmniAuth\Events\TwoFactorFallbackOtpRequested($user, $otp));

        return true;
    }

    /**
     * Verify a recovery code and remove it from the pool if valid (single-use).
     */
    public function verifyAndConsumeRecoveryCode(AuthTwoFactor $twoFactor, string $code): bool
    {
        $hashedCodes = $twoFactor->recovery_codes ?? [];

        foreach ($hashedCodes as $index => $hashedCode) {
            if (Hash::check($code, $hashedCode)) {
                unset($hashedCodes[$index]);
                $twoFactor->update(['recovery_codes' => array_values($hashedCodes)]);
                return true;
            }
        }

        return false;
    }

    /**
     * Regenerate emergency recovery codes for an active 2FA user.
     *
     * @return array<string> Plain text recovery codes to present once to the user
     */
    public function regenerateRecoveryCodes(Authenticatable|Model $user): array
    {
        $plainCodes = $this->generateRecoveryCodes(8);
        $hashedCodes = array_map(fn($code) => Hash::make($code), $plainCodes);

        AuthTwoFactor::where('user_id', $user->getAuthIdentifier())
            ->whereNotNull('confirmed_at')
            ->update(['recovery_codes' => $hashedCodes]);

        return $plainCodes;
    }

    /**
     * Generate an RFC 6238 TOTP code for a secret at a given timestamp.
     */
    public function calculateCode(string $secret, ?int $timestamp = null): string
    {
        $secretBytes = $this->base32Decode($secret);
        $timeSlice = (int) floor(($timestamp ?? time()) / 30);

        // Pack timeSlice into 64-bit big-endian integer
        $timeBytes = pack('N*', 0) . pack('N*', $timeSlice);
        $hmac = hash_hmac('sha1', $timeBytes, $secretBytes, true);

        // Dynamic truncation (RFC 4226 / RFC 6238)
        $offset = ord(substr($hmac, -1)) & 0x0F;
        $hashPart = substr($hmac, $offset, 4);
        $value = unpack('N', $hashPart)[1] & 0x7FFFFFFF;

        return str_pad((string) ($value % 1000000), 6, '0', STR_PAD_LEFT);
    }

    /**
     * Verify a 6-digit TOTP code against a secret with window drift tolerance.
     */
    public function verifyCode(string $secret, string $code, int $window = 1): bool
    {
        $currentTime = time();

        for ($i = -$window; $i <= $window; $i++) {
            $expectedCode = $this->calculateCode($secret, $currentTime + ($i * 30));
            if (hash_equals($expectedCode, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generate a cryptographically secure Base32 secret string.
     */
    public function generateSecret(int $length = 32): string
    {
        $secret = '';
        $alphabet = self::BASE32_ALPHABET;
        $max = strlen($alphabet) - 1;

        for ($i = 0; $i < $length; $i++) {
            $secret .= $alphabet[random_int(0, $max)];
        }

        return $secret;
    }

    /**
     * Generate a set of formatted emergency recovery codes.
     *
     * @return array<string>
     */
    public function generateRecoveryCodes(int $count = 8): array
    {
        $codes = [];

        for ($i = 0; $i < $count; $i++) {
            $codes[] = strtoupper(Str::random(5) . '-' . Str::random(5));
        }

        return $codes;
    }

    /**
     * Generate an otpauth:// URI for QR code generators and authenticator apps.
     */
    public function qrCodeUri(string $secret, Authenticatable|Model $user): string
    {
        $issuer = config('omni-auth.two_factor.issuer', config('app.name', 'Laravel'));
        $identifierColumn = config('omni-auth.identifier_column', 'email');
        $identifier = $user->{$identifierColumn} ?? $user->email ?? $user->getAuthIdentifier();

        $encodedIssuer = rawurlencode($issuer);
        $encodedIdentifier = rawurlencode((string) $identifier);

        return "otpauth://totp/{$encodedIssuer}:{$encodedIdentifier}?secret={$secret}&issuer={$encodedIssuer}&algorithm=SHA1&digits=6&period=30";
    }

    /**
     * Decode a Base32 string to binary bytes according to RFC 4648.
     */
    protected function base32Decode(string $base32): string
    {
        $base32 = strtoupper(rtrim($base32, '='));
        $alphabet = self::BASE32_ALPHABET;
        $buffer = 0;
        $bitsLeft = 0;
        $output = '';

        for ($i = 0, $len = strlen($base32); $i < $len; $i++) {
            $char = $base32[$i];
            $pos = strpos($alphabet, $char);

            if ($pos === false) {
                continue;
            }

            $buffer = ($buffer << 5) | $pos;
            $bitsLeft += 5;

            if ($bitsLeft >= 8) {
                $bitsLeft -= 8;
                $output .= chr(($buffer >> $bitsLeft) & 0xFF);
            }
        }

        return $output;
    }

    /**
     * Cache key for temporary two-factor challenges.
     */
    protected function challengeCacheKey(string $token): string
    {
        return 'omni_2fa_challenge:' . hash('sha256', $token);
    }

    /**
     * Resolve the configured cache store instance.
     */
    protected function cache(): \Illuminate\Contracts\Cache\Repository
    {
        $store = config('omni-auth.cache_store');

        return $store ? Cache::store($store) : Cache::store();
    }
}
