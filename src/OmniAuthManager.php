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
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use KaziOmar\OmniAuth\Services\ClientDetector;
use KaziOmar\OmniAuth\Services\CookieManager;
use Laravel\Sanctum\PersonalAccessToken;

class OmniAuthManager
{
    public function __construct(
        protected ClientDetector $clientDetector,
        protected CookieManager $cookieManager
    ) {}

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

        // 1. Rate Limiting Check (Brute-Force Protection)
        $rateLimitingEnabled = config('omni-auth.rate_limiting.enabled', true);
        $throttleKey = Str::transliterate(Str::lower($identifier) . '|' . $request->ip());

        if ($rateLimitingEnabled) {
            $maxAttempts = (int) config('omni-auth.rate_limiting.max_attempts', 5);
            $decaySeconds = (int) config('omni-auth.rate_limiting.decay_seconds', 60);

            if (RateLimiter::tooManyAttempts($throttleKey, $maxAttempts)) {
                $seconds = RateLimiter::availableIn($throttleKey);

                return response()->json([
                    'ok' => false,
                    'message' => "Too many login attempts. Please try again in {$seconds} seconds.",
                    'retry_after' => $seconds,
                ], 429);
            }
        }

        // 2. Resolve User from Database
        /** @var Model|null $user */
        $user = $userModelClass::where($identifierColumn, $identifier)->first();

        // 3. Verify Password
        if (!$user || !Hash::check($password, (string) $user->getAuthPassword())) {
            if ($rateLimitingEnabled) {
                RateLimiter::hit($throttleKey, (int) config('omni-auth.rate_limiting.decay_seconds', 60));
            }

            event(new Failed($guard, $user, $credentials));

            return response()->json([
                'ok' => false,
                'message' => 'Invalid credentials.',
            ], 401);
        }

        // 4. Success: Clear Rate Limiter and Dispatch Standard Login Event
        if ($rateLimitingEnabled) {
            RateLimiter::clear($throttleKey);
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

        // 2. Extract and validate incoming data
        if ($requestOrData instanceof FormRequest) {
            try {
                if (method_exists($requestOrData, 'setRedirector') && app()->bound(\Illuminate\Routing\Redirector::class)) {
                    $requestOrData->setRedirector(app(\Illuminate\Routing\Redirector::class));
                }
                if (method_exists($requestOrData, 'validateResolved')) {
                    $requestOrData->validateResolved();
                }
                $attributes = $requestOrData->validated();
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

            // Include validated fields along with any additional inputs present in request
            $attributes = array_merge($requestOrData->all(), $validator->validated());
        } else {
            // Raw array passed
            $attributes = $requestOrData;

            // If rules are configured or password_confirmation is provided, run validator
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

            $attributes = array_merge($attributes, $validator->validated());
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
                'user' => $user,
            ],
        ], 201);
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
        $accessTokenObj = $user->createToken('access_token', ['*'], $accessTokenExpiresAt);
        $accessToken = $accessTokenObj->plainTextToken;

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
                'user' => $user,
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
                'user' => $user,
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
            return response()->json([
                'ok' => false,
                'message' => 'Refresh token is missing.',
            ], 401);
        }

        // 2. Validate Refresh Token via Sanctum
        $tokenModel = PersonalAccessToken::findToken($refreshToken);

        if (!$tokenModel) {
            return response()->json([
                'ok' => false,
                'message' => 'Invalid or expired refresh token.',
            ], 401);
        }

        // Ensure token has refresh capability
        if (!$tokenModel->can('issue-access-token')) {
            return response()->json([
                'ok' => false,
                'message' => 'Invalid token capability for refresh.',
            ], 403);
        }

        // Check expiration
        if ($tokenModel->expires_at && $tokenModel->expires_at->isPast()) {
            $tokenModel->delete();

            return response()->json([
                'ok' => false,
                'message' => 'Refresh token has expired. Please log in again.',
            ], 401);
        }

        $user = $tokenModel->tokenable;

        if (!$user) {
            $tokenModel->delete();

            return response()->json([
                'ok' => false,
                'message' => 'Associated user account no longer exists.',
            ], 401);
        }

        // 3. Single-Use Rotation: Revoke old refresh token immediately to prevent replay attacks
        $tokenModel->delete();

        // 4. Issue new token pair
        return $this->issueTokenResponse($user, $request, 'Token refreshed successfully.');
    }

    /**
     * Log out the authenticated user, revoking the current access token and clearing cookies.
     */
    public function logout(?Request $request = null): JsonResponse
    {
        $request = $request ?? request();
        $guard = config('omni-auth.guard', 'sanctum');

        $user = auth($guard)->user();

        if ($user) {
            if (method_exists($user, 'currentAccessToken') && $user->currentAccessToken()) {
                $user->currentAccessToken()->delete();
            }

            event(new Logout($guard, $user));
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
}
