<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use KaziOmar\OmniAuth\Facades\Omni;

class AuthController extends Controller
{
    /**
     * Authenticate user credentials and return dual-mode tokens (Cookie / Bearer).
     */
    public function login(Request $request): JsonResponse
    {
        $identifierColumn = config('omni-auth.identifier_column', 'email');

        $credentials = $request->only(
            $identifierColumn,
            'email',
            'username',
            'phone',
            'password'
        );

        return Omni::attempt($credentials, $request);
    }

    /**
     * Register a new user with dynamic auto-hydration and dual-mode delivery.
     */
    public function register(Request $request): JsonResponse
    {
        return Omni::register($request);
    }

    /**
     * Refresh access and refresh tokens using single-use rotation.
     */
    public function refresh(Request $request): JsonResponse
    {
        return Omni::refresh($request);
    }

    /**
     * Log out authenticated user, revoking tokens and clearing cookies.
     */
    public function logout(Request $request): JsonResponse
    {
        $allDevices = filter_var($request->input('all_devices', false), FILTER_VALIDATE_BOOLEAN);

        return Omni::logout($request, $allDevices);
    }

    /**
     * Retrieve the currently authenticated user profile and permissions.
     */
    public function me(Request $request): JsonResponse
    {
        return Omni::me($request);
    }
}
