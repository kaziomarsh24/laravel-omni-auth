<?php

namespace KaziOmar\OmniAuth\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \Illuminate\Http\JsonResponse attempt(array $credentials, ?\Illuminate\Http\Request $request = null)
 * @method static \Illuminate\Http\JsonResponse register(\Illuminate\Http\Request|array $requestOrData, array $additionalData = [], ?bool $autoLogin = null, ?string $defaultRole = null)
 * @method static \Illuminate\Http\JsonResponse issueTokenResponse(\Illuminate\Contracts\Auth\Authenticatable $user, ?\Illuminate\Http\Request $request = null, string $message = 'Authenticated successfully.', int $status = 200)
 * @method static \Illuminate\Http\JsonResponse refresh(?\Illuminate\Http\Request $request = null)
 * @method static \Illuminate\Http\JsonResponse logout(?\Illuminate\Http\Request $request = null, bool $allDevices = false)
 * @method static \Illuminate\Http\JsonResponse me(?\Illuminate\Http\Request $request = null)
 * @method static array formatUserResponse(\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static \Illuminate\Contracts\Auth\Authenticatable|null user(?\Illuminate\Http\Request $request = null)
 * @method static bool isMobile(?\Illuminate\Http\Request $request = null)
 * @method static bool isWeb(?\Illuminate\Http\Request $request = null)
 * @method static \KaziOmar\OmniAuth\Services\CookieManager cookies()
 * @method static \KaziOmar\OmniAuth\Services\ClientDetector client()
 * @method static \KaziOmar\OmniAuth\Services\DeviceManager devices()
 * @method static \KaziOmar\OmniAuth\Services\TwoFactorManager twoFactor()
 * @method static \KaziOmar\OmniAuth\Services\SocialAuthManager social()
 * @method static \KaziOmar\OmniAuth\Services\PasswordResetManager passwordReset()
 * @method static bool deleteAccount(\Illuminate\Contracts\Auth\Authenticatable $user, ?string $password = null)
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
