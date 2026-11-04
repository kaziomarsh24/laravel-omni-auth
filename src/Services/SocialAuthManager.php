<?php

namespace KaziOmar\OmniAuth\Services;

use Exception;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use InvalidArgumentException;
use KaziOmar\OmniAuth\Models\AuthSocialAccount;
use KaziOmar\OmniAuth\OmniAuthManager;

class SocialAuthManager
{
    public function __construct(
        protected OmniAuthManager $authManager
    ) {}

    /**
     * Get provider configuration from omni-auth or services config.
     *
     * @return array<string, mixed>
     */
    public function getProviderConfig(string $provider): array
    {
        $config = config("omni-auth.social.providers.{$provider}", []);

        if (empty($config)) {
            $config = config("services.{$provider}", []);
        }

        return $config;
    }

    /**
     * Get the OAuth2 redirect URL for a social provider.
     */
    public function getRedirectUrl(string $provider, ?string $state = null): string
    {
        $state = $state ?? Str::random(40);
        $config = $this->getProviderConfig($provider);

        // 1. If Laravel Socialite is installed, use Socialite driver
        if (class_exists(\Laravel\Socialite\Facades\Socialite::class)) {
            try {
                return \Laravel\Socialite\Facades\Socialite::driver($provider)
                    ->stateless()
                    ->with(['state' => $state])
                    ->redirect()
                    ->getTargetUrl();
            } catch (Exception) {
                // Fall back to native OAuth generation below
            }
        }

        // 2. Native OAuth2 authorize URL generation
        $clientId = $config['client_id'] ?? '';
        $redirect = $config['redirect'] ?? url("/api/auth/social/{$provider}/callback");

        return match ($provider) {
            'google' => 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query([
                'client_id' => $clientId,
                'redirect_uri' => $redirect,
                'response_type' => 'code',
                'scope' => 'openid profile email',
                'access_type' => 'offline',
                'prompt' => 'consent',
                'state' => $state,
            ]),
            'github' => 'https://github.com/login/oauth/authorize?' . http_build_query([
                'client_id' => $clientId,
                'redirect_uri' => $redirect,
                'scope' => 'user:email read:user',
                'state' => $state,
            ]),
            'apple' => 'https://appleid.apple.com/auth/authorize?' . http_build_query([
                'client_id' => $clientId,
                'redirect_uri' => $redirect,
                'response_type' => 'code id_token',
                'response_mode' => 'form_post',
                'scope' => 'name email',
                'state' => $state,
            ]),
            default => throw new InvalidArgumentException("Unsupported social provider [{$provider}]."),
        };
    }

    /**
     * Handle OAuth callback from provider and authenticate or link account.
     *
     * @return array{response: mixed, user: Authenticatable&Model}
     */
    public function handleCallback(string $provider, ?string $code = null, array $requestData = []): array
    {
        $profile = $this->resolveProviderProfile($provider, $code, $requestData);
        $user = $this->findOrCreateUserForProfile($provider, $profile);

        $response = $this->authManager->respondWithDualModeTokens($user);

        return [
            'response' => $response,
            'user' => $user,
        ];
    }

    /**
     * Mobile native token exchange endpoint.
     * Accepts native identity tokens (e.g. Google ID Token, Apple JWT) directly from mobile SDKs.
     *
     * @param array<string, mixed> $extra
     * @return array{response: mixed, user: Authenticatable&Model}
     */
    public function exchangeMobileToken(string $provider, string $idToken, array $extra = []): array
    {
        $profile = match ($provider) {
            'google' => $this->verifyGoogleIdToken($idToken),
            'apple' => $this->verifyAppleIdentityToken($idToken, $extra),
            default => throw new InvalidArgumentException("Mobile native token exchange not supported for [{$provider}]."),
        };

        $user = $this->findOrCreateUserForProfile($provider, $profile);
        $response = $this->authManager->respondWithDualModeTokens($user);

        return [
            'response' => $response,
            'user' => $user,
        ];
    }

    /**
     * Verify a Google ID token via Google's tokeninfo endpoint or mock verification.
     *
     * @return array{id: string, email: string, name: ?string, avatar: ?string, email_verified: bool, data: array}
     */
    public function verifyGoogleIdToken(string $idToken): array
    {
        $config = $this->getProviderConfig('google');

        $response = Http::timeout(5)->get('https://oauth2.googleapis.com/tokeninfo', [
            'id_token' => $idToken,
        ]);

        if (!$response->successful()) {
            throw new InvalidArgumentException('Invalid or expired Google ID token: ' . ($response->json('error_description') ?? 'Verification failed.'));
        }

        $data = $response->json();

        // Verify audience matches expected client ID or mobile client IDs
        $validAudiences = array_filter(array_merge(
            [$config['client_id'] ?? null],
            $config['mobile_client_ids'] ?? []
        ));

        if (!empty($validAudiences) && !in_array($data['aud'] ?? '', $validAudiences, true)) {
            throw new InvalidArgumentException('Google ID token audience mismatch.');
        }

        // Verify expiration
        if (isset($data['exp']) && (int) $data['exp'] < time()) {
            throw new InvalidArgumentException('Google ID token has expired.');
        }

        $emailVerified = filter_var($data['email_verified'] ?? false, FILTER_VALIDATE_BOOLEAN);

        return [
            'id' => (string) ($data['sub'] ?? ''),
            'email' => (string) ($data['email'] ?? ''),
            'name' => $data['name'] ?? null,
            'avatar' => $data['picture'] ?? null,
            'email_verified' => $emailVerified,
            'data' => $data,
        ];
    }

    /**
     * Verify an Apple identity token (JWT) and extract user identity.
     *
     * @param array<string, mixed> $extra
     * @return array{id: string, email: ?string, name: ?string, avatar: null, email_verified: bool, data: array}
     */
    public function verifyAppleIdentityToken(string $idToken, array $extra = []): array
    {
        $parts = explode('.', $idToken);
        if (count($parts) !== 3) {
            throw new InvalidArgumentException('Invalid Apple identity token format.');
        }

        $payloadJson = $this->base64UrlDecode($parts[1]);
        $claims = json_decode($payloadJson, true);

        if (!is_array($claims)) {
            throw new InvalidArgumentException('Invalid Apple identity token claims.');
        }

        // Verify issuer
        if (($claims['iss'] ?? '') !== 'https://appleid.apple.com') {
            throw new InvalidArgumentException('Apple token issuer must be https://appleid.apple.com.');
        }

        // Verify expiration
        if (isset($claims['exp']) && (int) $claims['exp'] < time()) {
            throw new InvalidArgumentException('Apple identity token has expired.');
        }

        // Verify audience if configured
        $config = $this->getProviderConfig('apple');
        if (!empty($config['client_id']) && ($claims['aud'] ?? '') !== $config['client_id']) {
            throw new InvalidArgumentException('Apple identity token audience mismatch.');
        }

        // Apple only sends name on the first authorization
        $name = null;
        if (isset($extra['user']['name'])) {
            $userMeta = $extra['user']['name'];
            $firstName = $userMeta['firstName'] ?? $userMeta['givenName'] ?? '';
            $lastName = $userMeta['lastName'] ?? $userMeta['familyName'] ?? '';
            $name = trim("{$firstName} {$lastName}") ?: null;
        } elseif (isset($extra['name'])) {
            $name = (string) $extra['name'];
        }

        return [
            'id' => (string) ($claims['sub'] ?? ''),
            'email' => $claims['email'] ?? null,
            'name' => $name,
            'avatar' => null,
            'email_verified' => isset($claims['email_verified']) ? filter_var($claims['email_verified'], FILTER_VALIDATE_BOOLEAN) : true,
            'data' => $claims,
        ];
    }

    /**
     * Generate Sign In with Apple client_secret JWT signed with ES256.
     */
    public function generateAppleClientSecret(?int $ttlSeconds = 86400 * 180): string
    {
        $config = $this->getProviderConfig('apple');

        $teamId = $config['team_id'] ?? '';
        $keyId = $config['key_id'] ?? '';
        $clientId = $config['client_id'] ?? '';
        $privateKey = $config['private_key'] ?? '';

        if (empty($teamId) || empty($keyId) || empty($clientId) || empty($privateKey)) {
            throw new InvalidArgumentException('Apple credentials (team_id, key_id, client_id, private_key) must be configured.');
        }

        // Ensure PEM formatting for private key
        if (!str_contains($privateKey, 'BEGIN PRIVATE KEY') && !str_contains($privateKey, 'BEGIN EC PRIVATE KEY')) {
            $privateKey = "-----BEGIN PRIVATE KEY-----\n" . wordwrap(trim($privateKey), 64, "\n", true) . "\n-----END PRIVATE KEY-----";
        }

        $now = time();
        $header = [
            'alg' => 'ES256',
            'kid' => $keyId,
            'typ' => 'JWT',
        ];

        $payload = [
            'iss' => $teamId,
            'iat' => $now,
            'exp' => $now + $ttlSeconds,
            'aud' => 'https://appleid.apple.com',
            'sub' => $clientId,
        ];

        $encodedHeader = $this->base64UrlEncode(json_encode($header, JSON_THROW_ON_ERROR));
        $encodedPayload = $this->base64UrlEncode(json_encode($payload, JSON_THROW_ON_ERROR));
        $dataToSign = "{$encodedHeader}.{$encodedPayload}";

        $derSignature = '';
        $signed = openssl_sign($dataToSign, $derSignature, $privateKey, OPENSSL_ALGO_SHA256);

        if (!$signed) {
            throw new Exception('Failed to sign Apple client secret with ES256: ' . openssl_error_string());
        }

        $rawSignature = $this->derToRawSignature($derSignature);
        $encodedSignature = $this->base64UrlEncode($rawSignature);

        return "{$dataToSign}.{$encodedSignature}";
    }

    /**
     * Find existing user or create one with intelligent account linking.
     */
    public function findOrCreateUserForProfile(string $provider, array $profile): Authenticatable|Model
    {
        $providerId = (string) $profile['id'];
        $email = $profile['email'] ?? null;

        // 1. Look for existing linked social account
        /** @var AuthSocialAccount|null $socialAccount */
        $socialAccount = AuthSocialAccount::where('provider', $provider)
            ->where('provider_id', $providerId)
            ->first();

        if ($socialAccount) {
            // Update token or avatar if available
            $socialAccount->update(array_filter([
                'token' => $profile['token'] ?? null,
                'refresh_token' => $profile['refresh_token'] ?? null,
                'avatar' => $profile['avatar'] ?? null,
                'data' => $profile['data'] ?? null,
            ]));

            return $socialAccount->user;
        }

        $userModelClass = config('omni-auth.user_model', 'App\\Models\\User');

        // 2. Intelligent Account Linking by Email
        $autoLink = (bool) config('omni-auth.social.auto_link_by_email', true);

        if ($email && $autoLink) {
            /** @var (Authenticatable&Model)|null $existingUser */
            $existingUser = $userModelClass::where('email', $email)->first();

            if ($existingUser) {
                // Link this provider to the existing account
                AuthSocialAccount::create([
                    'user_id' => $existingUser->getAuthIdentifier(),
                    'provider' => $provider,
                    'provider_id' => $providerId,
                    'token' => $profile['token'] ?? null,
                    'refresh_token' => $profile['refresh_token'] ?? null,
                    'avatar' => $profile['avatar'] ?? null,
                    'data' => $profile['data'] ?? null,
                ]);

                // Auto-verify email if provider confirmed it and user is unverified
                if (empty($existingUser->email_verified_at) && !empty($profile['email_verified'])) {
                    $existingUser->email_verified_at = now();
                    $existingUser->save();
                }

                return $existingUser;
            }
        }

        // 3. Create a brand new user account
        $name = $profile['name'] ?? ($email ? explode('@', $email)[0] : 'User');
        $userData = [
            'name' => $name,
            'email' => $email ?? "{$provider}_{$providerId}@omni-auth.local",
            'password' => Hash::make(Str::random(32)),
        ];

        if (!empty($profile['email_verified'])) {
            $userData['email_verified_at'] = now();
        }

        /** @var Authenticatable&Model $newUser */
        $newUser = $userModelClass::create($userData);

        AuthSocialAccount::create([
            'user_id' => $newUser->getAuthIdentifier(),
            'provider' => $provider,
            'provider_id' => $providerId,
            'token' => $profile['token'] ?? null,
            'refresh_token' => $profile['refresh_token'] ?? null,
            'avatar' => $profile['avatar'] ?? null,
            'data' => $profile['data'] ?? null,
        ]);

        event(new \Illuminate\Auth\Events\Registered($newUser));

        return $newUser;
    }

    /**
     * Get all linked social accounts for an authenticated user.
     */
    public function linkedAccounts(Authenticatable|Model $user): Collection
    {
        return AuthSocialAccount::where('user_id', $user->getAuthIdentifier())
            ->get(['id', 'provider', 'avatar', 'created_at']);
    }

    /**
     * Unlink a social provider from the user's account safely.
     * Prevents unlinking if the user has no password set and no other linked accounts.
     */
    public function unlink(Authenticatable|Model $user, string $provider): bool
    {
        $accountsCount = AuthSocialAccount::where('user_id', $user->getAuthIdentifier())->count();
        $hasPassword = !empty($user->password);

        if ($accountsCount <= 1 && !$hasPassword) {
            throw new InvalidArgumentException('Cannot unlink provider: Account has no password set or secondary authentication method.');
        }

        return (bool) AuthSocialAccount::where('user_id', $user->getAuthIdentifier())
            ->where('provider', $provider)
            ->delete();
    }

    /**
     * Resolve provider profile from Socialite or fallback HTTP token exchange.
     *
     * @return array{id: string, email: ?string, name: ?string, avatar: ?string, token: ?string, refresh_token: ?string, email_verified: bool, data: array}
     */
    protected function resolveProviderProfile(string $provider, ?string $code, array $requestData): array
    {
        if (class_exists(\Laravel\Socialite\Facades\Socialite::class)) {
            try {
                $socialiteUser = \Laravel\Socialite\Facades\Socialite::driver($provider)->stateless()->user();

                return [
                    'id' => (string) $socialiteUser->getId(),
                    'email' => $socialiteUser->getEmail(),
                    'name' => $socialiteUser->getName() ?? $socialiteUser->getNickname(),
                    'avatar' => $socialiteUser->getAvatar(),
                    'token' => $socialiteUser->token ?? null,
                    'refresh_token' => $socialiteUser->refreshToken ?? null,
                    'email_verified' => true,
                    'data' => (array) ($socialiteUser->user ?? []),
                ];
            } catch (Exception) {
                // Fall back to native code exchange
            }
        }

        if (empty($code)) {
            throw new InvalidArgumentException('Authorization code is required for social callback.');
        }

        $config = $this->getProviderConfig($provider);
        $redirect = $config['redirect'] ?? url("/api/auth/social/{$provider}/callback");

        return match ($provider) {
            'google' => $this->exchangeGoogleCode($code, $config, $redirect),
            'github' => $this->exchangeGithubCode($code, $config, $redirect),
            default => throw new InvalidArgumentException("Automatic code exchange not implemented for [{$provider}]."),
        };
    }

    /**
     * Exchange OAuth code for Google profile.
     */
    protected function exchangeGoogleCode(string $code, array $config, string $redirect): array
    {
        $tokenRes = Http::asForm()->post('https://oauth2.googleapis.com/token', [
            'client_id' => $config['client_id'] ?? '',
            'client_secret' => $config['client_secret'] ?? '',
            'code' => $code,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $redirect,
        ]);

        if (!$tokenRes->successful()) {
            throw new InvalidArgumentException('Failed to exchange Google OAuth code: ' . $tokenRes->body());
        }

        $tokenData = $tokenRes->json();
        $accessToken = $tokenData['access_token'] ?? null;

        $userRes = Http::withToken($accessToken)->get('https://www.googleapis.com/oauth2/v3/userinfo');
        $userData = $userRes->json();

        return [
            'id' => (string) ($userData['sub'] ?? ''),
            'email' => $userData['email'] ?? null,
            'name' => $userData['name'] ?? null,
            'avatar' => $userData['picture'] ?? null,
            'token' => $accessToken,
            'refresh_token' => $tokenData['refresh_token'] ?? null,
            'email_verified' => filter_var($userData['email_verified'] ?? false, FILTER_VALIDATE_BOOLEAN),
            'data' => $userData,
        ];
    }

    /**
     * Exchange OAuth code for GitHub profile.
     */
    protected function exchangeGithubCode(string $code, array $config, string $redirect): array
    {
        $tokenRes = Http::acceptJson()->asForm()->post('https://github.com/login/oauth/access_token', [
            'client_id' => $config['client_id'] ?? '',
            'client_secret' => $config['client_secret'] ?? '',
            'code' => $code,
            'redirect_uri' => $redirect,
        ]);

        if (!$tokenRes->successful()) {
            throw new InvalidArgumentException('Failed to exchange GitHub OAuth code: ' . $tokenRes->body());
        }

        $tokenData = $tokenRes->json();
        $accessToken = $tokenData['access_token'] ?? null;

        $userRes = Http::withToken($accessToken)->get('https://api.github.com/user');
        $userData = $userRes->json();

        // GitHub user email may be private; fetch primary email
        $email = $userData['email'] ?? null;
        if (!$email) {
            $emailsRes = Http::withToken($accessToken)->get('https://api.github.com/user/emails');
            if ($emailsRes->successful()) {
                foreach ($emailsRes->json() as $emailRecord) {
                    if (!empty($emailRecord['primary'])) {
                        $email = $emailRecord['email'];
                        break;
                    }
                }
            }
        }

        return [
            'id' => (string) ($userData['id'] ?? ''),
            'email' => $email,
            'name' => $userData['name'] ?? $userData['login'] ?? null,
            'avatar' => $userData['avatar_url'] ?? null,
            'token' => $accessToken,
            'refresh_token' => null,
            'email_verified' => true,
            'data' => $userData,
        ];
    }

    /**
     * Convert an OpenSSL DER-encoded ECDSA signature to raw 64-byte IEEE P1363 (r || s).
     */
    public function derToRawSignature(string $der): string
    {
        $pos = 2;
        if (ord($der[1]) & 0x80) {
            $pos = 2 + (ord($der[1]) & 0x7F);
        }

        $pos++; // skip r type marker (0x02)
        $rLen = ord($der[$pos++]);
        $r = substr($der, $pos, $rLen);
        $pos += $rLen;

        $pos++; // skip s type marker (0x02)
        $sLen = ord($der[$pos++]);
        $s = substr($der, $pos, $sLen);

        $r = str_pad(ltrim($r, "\x00"), 32, "\x00", STR_PAD_LEFT);
        $s = str_pad(ltrim($s, "\x00"), 32, "\x00", STR_PAD_LEFT);

        return $r . $s;
    }

    /**
     * Base64URL encode without padding.
     */
    public function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64URL decode with padding restoration.
     */
    public function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        return (string) base64_decode(strtr($data, '-_', '+/'));
    }
}
