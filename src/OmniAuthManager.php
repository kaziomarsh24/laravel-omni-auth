<?php

namespace KaziOmar\OmniAuth;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\Registered;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use KaziOmar\OmniAuth\Http\Resources\OmniUserResource;
use KaziOmar\OmniAuth\Services\ClientDetector;
use KaziOmar\OmniAuth\Services\CookieManager;
use KaziOmar\OmniAuth\Services\DeviceManager;
use KaziOmar\OmniAuth\Services\PasswordResetManager;
use KaziOmar\OmniAuth\Services\SocialAuthManager;
use KaziOmar\OmniAuth\Services\TwoFactorManager;
use Laravel\Sanctum\PersonalAccessToken;

class OmniAuthManager
{
    protected ?SocialAuthManager $socialManager = null;
    protected ?PasswordResetManager $passwordResetManager = null;

    public function __construct(
        protected ClientDetector $clientDetector,
        protected CookieManager $cookieManager,
        protected DeviceManager $deviceManager,
        protected TwoFactorManager $twoFactorManager
    ) {}

    /**
     * Access the password reset, verification, and account management service.
     */
    public function passwordReset(): PasswordResetManager
    {
        return $this->passwordResetManager ??= new PasswordResetManager($this->deviceManager);
    }

    /**
     * Delete user account permanently complying with App Store guidelines & GDPR.
     */
    public function deleteAccount(Authenticatable|Model $user, ?string $password = null): bool
    {
        return $this->passwordReset()->deleteAccount($user, $password);
    }

    /**
     * Access the social authentication manager.
     */
    public function social(): SocialAuthManager
    {
        return $this->socialManager ??= new SocialAuthManager($this);
    }

    /**
     * Access the two-factor authentication service.
     */
    public function twoFactor(): TwoFactorManager
    {
        return $this->twoFactorManager;
    }

    /**
     * Access the multi-device & FCM management service.
     */
    public function devices(): DeviceManager
    {
        return $this->deviceManager;
    }

    /**
     * Attempt to authenticate a user using credentials (e.g. email/username/phone & password).
     * Includes built-in rate limiting, standard auth events, and dual-mode token delivery.
     */
    public function attempt(array $credentials, ?Request $request = null): JsonResponse
    {
        $request = $request ?? request();
        $guard = config('omni-auth.guard', 'sanctum');
        $userModelClass = config('omni-auth.user_model', 'App\\Models\\User');

        $identifierColumn = config('omni-auth.identifier_column', 'email');
        
        // Auto-detect identifier key if 'email' is not in credentials
        $identifier = $credentials[$identifierColumn] ?? $credentials['email'] ?? $credentials['username'] ?? $credentials['phone'] ?? null;
        $password = $credentials['password'] ?? null;

        if (!$identifier || !$password) {
            return response()->json([
                'ok' => false,
                'message' => 'Credentials must include an identifier and password.',
            ], 422);
        }

        // 1. Rate Limiting Check (Brute-Force & Distributed Botnet Protection)
        $rateLimitingEnabled = config('omni-auth.rate_limiting.enabled', true);
        $throttleKey = Str::transliterate(Str::lower($identifier) . '|' . $request->ip());
        $globalKey = Str::transliterate(Str::lower($identifier) . '|global');

        if ($rateLimitingEnabled) {
            $maxAttempts = (int) config('omni-auth.rate_limiting.max_attempts', 5);
            $decaySeconds = (int) config('omni-auth.rate_limiting.decay_seconds', 60);
            $globalMax = (int) config('omni-auth.rate_limiting.global_max_attempts', 20);
            $globalDecay = (int) config('omni-auth.rate_limiting.global_decay_seconds', 900);

            if (RateLimiter::tooManyAttempts($throttleKey, $maxAttempts)) {
                $seconds = RateLimiter::availableIn($throttleKey);

                return response()->json([
                    'ok' => false,
                    'message' => "Too many login attempts. Please try again in {$seconds} seconds.",
                    'retry_after' => $seconds,
                ], 429);
            }

            if (RateLimiter::tooManyAttempts($globalKey, $globalMax)) {
                $seconds = RateLimiter::availableIn($globalKey);

                return response()->json([
                    'ok' => false,
                    'message' => "Account is temporarily locked due to multiple failed login attempts across networks. Please try again in {$seconds} seconds.",
                    'retry_after' => $seconds,
                ], 429);
            }
        }

        // 2. Resolve User from Database
        /** @var Model|null $user */
        $user = $userModelClass::where($identifierColumn, $identifier)->first();

        // 3. Verify Password with Side-Channel Timing Attack Prevention
        $userPassword = $user ? (string) $user->getAuthPassword() : '$2y$12$e80MvQ1k48p7f0BqK3B0vOK0UkmZ84F1n8jW9c5S4E1Q2w3E4r5T6';
        $passwordValid = Hash::check($password, $userPassword);

        if (!$user || !$passwordValid) {
            if ($rateLimitingEnabled) {
                RateLimiter::hit($throttleKey, (int) config('omni-auth.rate_limiting.decay_seconds', 60));
                RateLimiter::hit($globalKey, (int) config('omni-auth.rate_limiting.global_decay_seconds', 900));
            }

            event(new Failed($guard, $user, $credentials));

            return response()->json([
                'ok' => false,
                'message' => 'Invalid credentials.',
            ], 401);
        }

        // 4. Two-Factor Authentication Challenge Check (Must precede Login event)
        if (Features::enabled(Features::twoFactorAuth()) && $this->twoFactorManager->isEnabled($user)) {
            $twoFactorToken = $this->twoFactorManager->createChallengeToken($user);

            return response()->json([
                'ok' => true,
                'message' => 'Two-factor authentication is required.',
                'data' => [
                    'requires_2fa' => true,
                    'two_factor_token' => $twoFactorToken,
                    'expires_in' => (int) config('omni-auth.two_factor.challenge_ttl', 5) * 60,
                ],
            ]);
        }

        // 5. Success: Clear Rate Limiter and Dispatch Standard Login Event
        if ($rateLimitingEnabled) {
            RateLimiter::clear($throttleKey);
            RateLimiter::clear($globalKey);
        }

        event(new Login($guard, $user, false));

        return $this->issueTokenResponse($user, $request, 'Logged in successfully.');
    }

    /**
     * Register a new user with zero boilerplate, dynamic auto-hydration, and dual-mode token delivery.
     * Supports FormRequest, standard Request, or raw array data.
     *
     * @param Request|array $requestOrData
     * @param array $additionalData Additional attributes to merge into the user record
     * @param bool|null $autoLogin Whether to automatically log the user in after registration
     * @param string|null $defaultRole Specific role to assign upon registration
     */
    public function register(
        Request|array $requestOrData,
        array $additionalData = [],
        ?bool $autoLogin = null,
        ?string $defaultRole = null
    ): JsonResponse {
        // 1. Check if Registration feature is enabled
        if (!Features::enabled(Features::registration())) {
            return response()->json([
                'ok' => false,
                'message' => 'Registration feature is disabled.',
            ], 403);
        }

        $userModelClass = config('omni-auth.user_model', 'App\\Models\\User');
        $identifierColumn = config('omni-auth.identifier_column', 'email');
        $table = (new $userModelClass())->getTable();

        $request = $requestOrData instanceof Request ? $requestOrData : request();

        $guardedKeys = array_merge([
            'id', 'is_admin', 'is_staff', 'is_superuser', 'role', 'roles', 'permissions',
            'status', 'is_active', 'tenant_id', 'email_verified_at', 'remember_token',
            'password_resets', 'created_at', 'updated_at'
        ], (array) config('omni-auth.registration.guarded', []));

        // 2. Extract and validate incoming data
        if ($requestOrData instanceof FormRequest) {
            try {
                if (method_exists($requestOrData, 'setRedirector') && app()->bound(\Illuminate\Routing\Redirector::class)) {
                    $requestOrData->setRedirector(app(\Illuminate\Routing\Redirector::class));
                }
                if (method_exists($requestOrData, 'validateResolved')) {
                    $requestOrData->validateResolved();
                }
                $attributes = array_diff_key($requestOrData->validated(), array_flip($guardedKeys));
            } catch (ValidationException $e) {
                return response()->json([
                    'ok' => false,
                    'message' => $e->getMessage(),
                    'errors' => $e->errors(),
                ], 422);
            }
        } elseif ($requestOrData instanceof Request) {
            $rules = config('omni-auth.registration.rules') ?? [
                'name' => ['required', 'string', 'max:255'],
                $identifierColumn => ['required', 'string', $identifierColumn === 'email' ? 'email' : 'string', 'max:255', "unique:{$table},{$identifierColumn}"],
                'password' => ['required', 'string', 'min:8', 'confirmed'],
            ];

            $validator = Validator::make($requestOrData->all(), $rules);

            if ($validator->fails()) {
                return response()->json([
                    'ok' => false,
                    'message' => 'The given data was invalid.',
                    'errors' => $validator->errors(),
                ], 422);
            }

            $allowedAttributes = config('omni-auth.registration.allowed_attributes');
            if (!empty($allowedAttributes) && is_array($allowedAttributes)) {
                $attributes = array_intersect_key($requestOrData->all(), array_flip($allowedAttributes));
                $attributes = array_merge($attributes, $validator->validated());
            } else {
                $safeInput = array_diff_key($requestOrData->all(), array_flip($guardedKeys));
                $attributes = array_merge($safeInput, $validator->validated());
            }
            $attributes = array_diff_key($attributes, array_flip($guardedKeys));
        } else {
            // Raw array passed
            $attributes = $requestOrData;

            $rules = config('omni-auth.registration.rules') ?? [
                'name' => ['required', 'string', 'max:255'],
                $identifierColumn => ['required', 'string', $identifierColumn === 'email' ? 'email' : 'string', 'max:255', "unique:{$table},{$identifierColumn}"],
                'password' => ['required', 'string', 'min:8', isset($attributes['password_confirmation']) ? 'confirmed' : 'nullable'],
            ];

            $validator = Validator::make($attributes, $rules);

            if ($validator->fails()) {
                return response()->json([
                    'ok' => false,
                    'message' => 'The given data was invalid.',
                    'errors' => $validator->errors(),
                ], 422);
            }

            $allowedAttributes = config('omni-auth.registration.allowed_attributes');
            if (!empty($allowedAttributes) && is_array($allowedAttributes)) {
                $attributes = array_intersect_key($attributes, array_flip($allowedAttributes));
                $attributes = array_merge($attributes, $validator->validated());
            } else {
                $safeInput = array_diff_key($attributes, array_flip($guardedKeys));
                $attributes = array_merge($safeInput, $validator->validated());
            }
            $attributes = array_diff_key($attributes, array_flip($guardedKeys));
        }

        // 3. Merge additional explicit data passed by developer
        if (!empty($additionalData)) {
            $attributes = array_merge($attributes, $additionalData);
        }

        // 4. Sanitize attributes: strip confirmation keys
        unset(
            $attributes['password_confirmation'],
            $attributes['passwordConfirmation'],
            $attributes['password_confirm']
        );

        // 5. Auto-hash password if unhashed
        if (isset($attributes['password']) && is_string($attributes['password'])) {
            $info = Hash::info($attributes['password']);
            if (($info['algo'] ?? null) === null) {
                $attributes['password'] = Hash::make($attributes['password']);
            }
        }

        // 6. Auto-Hydrate and Save User
        /** @var Model $user */
        $user = new $userModelClass();
        $user->fill($attributes);
        $user->save();

        // 7. Auto-Assign Role (Spatie Permission or 'role' column)
        $roleToAssign = $defaultRole
            ?? config('omni-auth.registration.default_role')
            ?? config('omni-auth.default_role');

        if ($roleToAssign) {
            if (method_exists($user, 'assignRole')) {
                $user->assignRole($roleToAssign);
            } elseif (in_array('role', $user->getFillable(), true) || isset($user->role) || Schema::hasColumn($table, 'role')) {
                $user->role = $roleToAssign;
                $user->save();
            }
        }

        // 8. Fire standard Laravel Registered event
        event(new Registered($user));

        // 9. Delivery: Auto-login (Dual-mode) or 201 Created JSON response
        $shouldAutoLogin = $autoLogin ?? config('omni-auth.registration.auto_login', true);

        if ($shouldAutoLogin) {
            return $this->issueTokenResponse($user, $request, 'Registered and authenticated successfully.', 201);
        }

        return response()->json([
            'ok' => true,
            'message' => 'User registered successfully.',
            'data' => [
                'user' => $this->formatUserResponse($user),
            ],
        ], 201);
    }

    /**
     * Alias for issueTokenResponse, returning dual-mode tokens according to client type.
     */
    public function respondWithDualModeTokens(Authenticatable|Model $user, ?Request $request = null, string $message = 'Authenticated successfully.', int $status = 200): JsonResponse
    {
        return $this->issueTokenResponse($user, $request, $message, $status);
    }

    /**
     * Issue access and refresh tokens for a user, formatting output according to client type.
     */
    public function issueTokenResponse(Authenticatable|Model $user, ?Request $request = null, string $message = 'Authenticated successfully.', int $status = 200): JsonResponse
    {
        $request = $request ?? request();

        $accessTtl = (int) config('omni-auth.tokens.access_token_ttl', 15);
        $refreshTtl = (int) config('omni-auth.tokens.refresh_token_ttl', 43200);

        // 1. Generate Access Token via Sanctum
        $accessTokenExpiresAt = now()->addMinutes($accessTtl);
        $accessTokenObj = $user->createToken('access_token', ['access-api'], $accessTokenExpiresAt);
        $accessToken = $accessTokenObj->plainTextToken;

        // Track active device session & FCM token if deviceTracking feature is enabled
        if (Features::enabled(Features::deviceTracking())) {
            $this->deviceManager->track($user, $request, $accessTokenObj->accessToken);
        }

        // 2. Generate Refresh Token via Sanctum (if token rotation is enabled)
        $refreshToken = null;
        if (Features::enabled(Features::tokenRotation())) {
            $refreshTokenExpiresAt = now()->addMinutes($refreshTtl);
            $refreshTokenObj = $user->createToken('refresh_token', ['issue-access-token'], $refreshTokenExpiresAt);
            $refreshToken = $refreshTokenObj->plainTextToken;
        }

        $isMobile = $this->clientDetector->isMobile($request);

        // 3. Mobile Client Delivery: Return tokens directly in JSON body
        if ($isMobile) {
            $responseData = [
                'access_token' => $accessToken,
                'token_type' => 'Bearer',
                'expires_in' => $accessTtl * 60,
                'user' => $this->formatUserResponse($user),
            ];

            if ($refreshToken) {
                $responseData['refresh_token'] = $refreshToken;
            }

            return response()->json([
                'ok' => true,
                'message' => $message,
                'data' => $responseData,
            ], $status);
        }

        // 4. Web Client Delivery: Deliver in HttpOnly, SameSite secure cookies
        $response = response()->json([
            'ok' => true,
            'message' => $message,
            'data' => [
                'user' => $this->formatUserResponse($user),
            ],
        ], $status);

        return $this->cookieManager->attachTokens($response, $accessToken, $refreshToken, $request);
    }

    /**
     * Refresh an expired access token using a valid single-use refresh token.
     * Enforces Single-Use Refresh Token Rotation: the old refresh token is revoked immediately.
     */
    public function refresh(?Request $request = null): JsonResponse
    {
        $request = $request ?? request();

        // 1. Extract Refresh Token from Cookie (Web) or Header/Body (Mobile)
        $refreshToken = null;

        if ($this->clientDetector->isWeb($request)) {
            $refreshToken = $this->cookieManager->getRefreshTokenFromCookie($request);
        }

        if (!$refreshToken) {
            $refreshToken = $request->header('X-Refresh-Token')
                ?? $request->input('refresh_token')
                ?? $this->cookieManager->getRefreshTokenFromCookie($request);
        }

        if (!$refreshToken) {
            return $this->unauthenticatedRefreshResponse('Refresh token is missing.', $request, 401);
        }

        // Replay Attack Detection: Verify if this refresh token was already rotated and revoked
        $tokenHash = hash('sha256', $refreshToken);
        $revokedKey = 'omni_revoked_token:' . $tokenHash;

        if ($this->cache()->has($revokedKey)) {
            $compromisedUserId = $this->cache()->get($revokedKey);
            $userModelClass = config('omni-auth.user_model', 'App\\Models\\User');

            if ($compromisedUserId) {
                $compromisedUser = $userModelClass::find($compromisedUserId);
                if ($compromisedUser && method_exists($compromisedUser, 'tokens')) {
                    // Security Lockout: Token theft detected! Invalidate all sessions for this account.
                    $compromisedUser->tokens()->delete();
                }
            }

            return $this->unauthenticatedRefreshResponse(
                'Security alert: Token reuse detected. All active sessions have been terminated for security. Please log in again.',
                $request,
                401
            );
        }

        // 2. Validate Refresh Token via Sanctum
        $tokenModel = PersonalAccessToken::findToken($refreshToken);

        if (!$tokenModel) {
            return $this->unauthenticatedRefreshResponse('Invalid or expired refresh token.', $request, 401);
        }

        // Ensure token model is strictly a refresh_token and has refresh capability
        if ($tokenModel->name !== 'refresh_token' || !$tokenModel->can('issue-access-token')) {
            return $this->unauthenticatedRefreshResponse('Invalid token capability for refresh.', $request, 403);
        }

        // Check expiration
        if ($tokenModel->expires_at && $tokenModel->expires_at->isPast()) {
            $tokenModel->delete();

            return $this->unauthenticatedRefreshResponse('Refresh token has expired. Please log in again.', $request, 401);
        }

        $user = $tokenModel->tokenable;

        if (!$user) {
            $tokenModel->delete();

            return $this->unauthenticatedRefreshResponse('Associated user account no longer exists.', $request, 401);
        }

        // 3. Single-Use Rotation: Revoke old refresh token immediately to prevent replay attacks
        $tokenModel->delete();

        // Record the revoked token hash in cache to detect any future replay attempts
        $refreshTtl = (int) config('omni-auth.tokens.refresh_token_ttl', 43200);
        $this->cache()->put($revokedKey, $user->getAuthIdentifier(), now()->addMinutes($refreshTtl));

        // 4. Issue new token pair
        return $this->issueTokenResponse($user, $request, 'Token refreshed successfully.');
    }

    /**
     * Return a standardized unauthorized/forbidden response for refresh failures,
     * ensuring browser cookies are cleared immediately for Web clients.
     */
    protected function unauthenticatedRefreshResponse(string $message, Request $request, int $status = 401): JsonResponse
    {
        $response = response()->json([
            'ok' => false,
            'message' => $message,
        ], $status);

        if ($this->clientDetector->isWeb($request)) {
            $response = $this->cookieManager->forgetTokens($response);
        }

        return $response;
    }

    /**
     * Log out the authenticated user, revoking tokens and clearing cookies.
     * Also revokes the refresh token from database if present, preventing token reuse.
     *
     * @param Request|null $request
     * @param bool $allDevices If true, revokes all personal access tokens for this user
     */
    public function logout(?Request $request = null, bool $allDevices = false): JsonResponse
    {
        $request = $request ?? request();
        $guard = config('omni-auth.guard', 'sanctum');

        $user = auth($guard)->user();

        if ($user) {
            if ($allDevices && method_exists($user, 'tokens')) {
                $user->tokens()->delete();
                if (Features::enabled(Features::deviceTracking())) {
                    $this->deviceManager->logoutOthers($user, $request);
                    $this->deviceManager->cleanupOnLogout($user, $request);
                }
            } elseif (method_exists($user, 'currentAccessToken') && $user->currentAccessToken()) {
                $user->currentAccessToken()->delete();
                if (Features::enabled(Features::deviceTracking())) {
                    $this->deviceManager->cleanupOnLogout($user, $request);
                }
            } else {
                if (Features::enabled(Features::deviceTracking())) {
                    $this->deviceManager->cleanupOnLogout($user, $request);
                }
            }

            event(new Logout($guard, $user));
        }

        // Revoke the refresh token from database if present in cookie, header, or body
        $refreshToken = $this->cookieManager->getRefreshTokenFromCookie($request)
            ?? $request->header('X-Refresh-Token')
            ?? $request->input('refresh_token');

        if ($refreshToken) {
            $tokenModel = PersonalAccessToken::findToken($refreshToken);
            if ($tokenModel) {
                $tokenModel->delete();
            }
        }

        $response = response()->json([
            'ok' => true,
            'message' => 'Logged out successfully.',
        ]);

        // If Web client, attach expired cookies to ensure the browser clears tokens immediately
        if ($this->clientDetector->isWeb($request)) {
            $response = $this->cookieManager->forgetTokens($response);
        }

        return $response;
    }

    /**
     * Format the user model for authentication responses using the configured
     * JsonResource (default: OmniUserResource) or a developer-provided custom Resource.
     */
    public function formatUserResponse(Authenticatable|Model $user): array
    {
        $customResourceClass = config('omni-auth.user_resource');

        if ($customResourceClass && class_exists($customResourceClass)) {
            $resource = new $customResourceClass($user);
            return $resource->resolve(request());
        }

        return (new OmniUserResource($user))->resolve(request());
    }

    /**
     * Retrieve the currently authenticated user payload.
     */
    public function me(?Request $request = null): JsonResponse
    {
        $user = $this->user($request);

        if (!$user) {
            return response()->json([
                'ok' => false,
                'message' => 'Unauthenticated.',
            ], 401);
        }

        return response()->json([
            'ok' => true,
            'data' => [
                'user' => $this->formatUserResponse($user),
            ],
        ]);
    }

    /**
     * Retrieve the currently authenticated user.
     */
    public function user(?Request $request = null): ?Authenticatable
    {
        $guard = config('omni-auth.guard', 'sanctum');

        return auth($guard)->user();
    }

    /**
     * Helper to check if current request is from a mobile client.
     */
    public function isMobile(?Request $request = null): bool
    {
        return $this->clientDetector->isMobile($request ?? request());
    }

    /**
     * Helper to check if current request is from a web client.
     */
    public function isWeb(?Request $request = null): bool
    {
        return $this->clientDetector->isWeb($request ?? request());
    }

    /**
     * Access the cookie manager instance.
     */
    public function cookies(): CookieManager
    {
        return $this->cookieManager;
    }

    /**
     * Access the client detector instance.
     */
    public function client(): ClientDetector
    {
        return $this->clientDetector;
    }

    /**
     * Resolve the configured cache store instance.
     */
    public function cache(): \Illuminate\Contracts\Cache\Repository
    {
        $store = config('omni-auth.cache_store');

        return $store ? Cache::store($store) : Cache::store();
    }
}
