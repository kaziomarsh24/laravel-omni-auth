<?php

namespace KaziOmar\OmniAuth\Http\Controllers;

use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use KaziOmar\OmniAuth\Facades\Omni;
use KaziOmar\OmniAuth\Features;

class SocialAuthController extends Controller
{
    /**
     * Ensure social login feature is enabled.
     */
    protected function ensureFeatureEnabled(): ?JsonResponse
    {
        if (!Features::enabled(Features::socialLogin())) {
            return response()->json([
                'ok' => false,
                'message' => 'Social authentication feature is disabled.',
            ], 403);
        }

        return null;
    }

    /**
     * Get OAuth redirect URL or initiate redirect to social provider.
     */
    public function redirect(Request $request, string $provider): JsonResponse|RedirectResponse
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        try {
            $url = Omni::social()->getRedirectUrl($provider);

            if ($request->wantsJson()) {
                return response()->json([
                    'ok' => true,
                    'redirect_url' => $url,
                ]);
            }

            return redirect()->away($url);
        } catch (Exception $e) {
            return response()->json([
                'ok' => false,
                'message' => $e->getMessage(),
            ], 400);
        }
    }

    /**
     * Handle OAuth callback from provider.
     */
    public function callback(Request $request, string $provider): mixed
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        $code = $request->input('code') ?? $request->query('code');

        try {
            $result = Omni::social()->handleCallback($provider, $code, $request->all());

            return $result['response'];
        } catch (Exception $e) {
            return response()->json([
                'ok' => false,
                'message' => $e->getMessage(),
            ], 400);
        }
    }

    /**
     * Mobile native token exchange endpoint.
     * Exchanges Google ID Token or Apple Identity JWT for access & refresh tokens.
     */
    public function exchange(Request $request): mixed
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        // Support both id_token and token parameter names
        if (!$request->has('id_token') && $request->has('token')) {
            $request->merge(['id_token' => $request->input('token')]);
        }

        $validated = $request->validate([
            'provider' => ['required', 'string', 'in:google,apple'],
            'id_token' => ['required', 'string'],
            'user' => ['nullable', 'array'],
            'name' => ['nullable', 'string'],
        ]);

        try {
            $result = Omni::social()->exchangeMobileToken(
                $validated['provider'],
                $validated['id_token'],
                $request->all()
            );

            return $result['response'];
        } catch (Exception $e) {
            return response()->json([
                'ok' => false,
                'message' => $e->getMessage(),
            ], 400);
        }
    }

    /**
     * List linked social accounts for current authenticated user.
     */
    public function accounts(Request $request): JsonResponse
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        $accounts = Omni::social()->linkedAccounts($request->user());

        return response()->json([
            'ok' => true,
            'data' => [
                'accounts' => $accounts,
            ],
        ]);
    }

    /**
     * Unlink a social provider from current authenticated user.
     */
    public function unlink(Request $request, string $provider): JsonResponse
    {
        if ($error = $this->ensureFeatureEnabled()) {
            return $error;
        }

        try {
            Omni::social()->unlink($request->user(), $provider);

            return response()->json([
                'ok' => true,
                'message' => "Successfully unlinked {$provider} account.",
            ]);
        } catch (Exception $e) {
            return response()->json([
                'ok' => false,
                'message' => $e->getMessage(),
            ], 400);
        }
    }
}
