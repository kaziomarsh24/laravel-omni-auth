<?php

namespace KaziOmar\OmniAuth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use KaziOmar\OmniAuth\Services\ClientDetector;
use KaziOmar\OmniAuth\Services\CookieManager;

class OmniAuthManager
{
    public function __construct(
        protected ClientDetector $clientDetector,
        protected CookieManager $cookieManager
    ) {}

    /**
     * Attempt to authenticate a user using credentials (e.g. email & password).
     * Automatically delivers HttpOnly Cookies for Web clients or Bearer JSON for Mobile clients.
     */
    public function attempt(array $credentials, ?Request $request = null): JsonResponse
    {
        $request = $request ?? request();
        $userModelClass = config('omni-auth.user_model', 'App\\Models\\User');

        $email = $credentials['email'] ?? null;
        $password = $credentials['password'] ?? null;

        if (!$email || !$password) {
            return response()->json([
                'ok' => false,
                'message' => 'Email and password are required.',
            ], 422);
        }

        /** @var Model|null $user */
        $user = $userModelClass::where('email', $email)->first();

        if (!$user || !Hash::check($password, (string) $user->getAuthPassword())) {
            return response()->json([
                'ok' => false,
                'message' => 'Invalid email or password.',
            ], 401);
        }

        return $this->issueTokenResponse($user, $request, 'Logged in successfully.');
    }

    /**
     * Issue access and refresh tokens for a user, formatting output according to client type.
     */
    public function issueTokenResponse(Authenticatable|Model $user, ?Request $request = null, string $message = 'Authenticated successfully.'): JsonResponse
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
            ]);
        }

        // 4. Web Client Delivery: Deliver in HttpOnly, SameSite secure cookies
        $response = response()->json([
            'ok' => true,
            'message' => $message,
            'data' => [
                'user' => $user,
            ],
        ]);

        return $this->cookieManager->attachTokens($response, $accessToken, $refreshToken);
    }

    /**
     * Log out the authenticated user, revoking the current access token and clearing cookies.
     */
    public function logout(?Request $request = null): JsonResponse
    {
        $request = $request ?? request();
        $guard = config('omni-auth.guard', 'sanctum');

        $user = auth($guard)->user();

        if ($user && method_exists($user, 'currentAccessToken') && $user->currentAccessToken()) {
            $user->currentAccessToken()->delete();
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
