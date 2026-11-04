<?php

namespace KaziOmar\OmniAuth\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \Illuminate\Http\JsonResponse attempt(array $credentials, ?\Illuminate\Http\Request $request = null)
 * @method static \Illuminate\Http\JsonResponse issueTokenResponse(\Illuminate\Contracts\Auth\Authenticatable $user, ?\Illuminate\Http\Request $request = null, string $message = 'Authenticated successfully.')
 * @method static \Illuminate\Http\JsonResponse logout(?\Illuminate\Http\Request $request = null)
 * @method static \Illuminate\Contracts\Auth\Authenticatable|null user(?\Illuminate\Http\Request $request = null)
 * @method static bool isMobile(?\Illuminate\Http\Request $request = null)
 * @method static bool isWeb(?\Illuminate\Http\Request $request = null)
 * @method static \KaziOmar\OmniAuth\Services\CookieManager cookies()
 * @method static \KaziOmar\OmniAuth\Services\ClientDetector client()
 *
 * @see \KaziOmar\OmniAuth\OmniAuthManager
 */
class Omni extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'omni.auth';
    }
}
