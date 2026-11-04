<?php

namespace KaziOmar\OmniAuth;

use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use KaziOmar\OmniAuth\Http\Middleware\OmniAuthenticate;
use KaziOmar\OmniAuth\Services\ClientDetector;
use KaziOmar\OmniAuth\Services\CookieManager;
use KaziOmar\OmniAuth\Services\DeviceManager;
use KaziOmar\OmniAuth\Services\TwoFactorManager;
use Laravel\Sanctum\Sanctum;

class OmniAuthServiceProvider extends ServiceProvider
{
    /**
     * Register package services in the container.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/omni-auth.php', 'omni-auth');

        $this->app->singleton(ClientDetector::class, function () {
            return new ClientDetector();
        });

        $this->app->singleton(CookieManager::class, function () {
            return new CookieManager();
        });

        $this->app->singleton(DeviceManager::class, function () {
            return new DeviceManager();
        });

        $this->app->singleton(TwoFactorManager::class, function () {
            return new TwoFactorManager();
        });

        $this->app->singleton('omni.auth', function ($app) {
            return new OmniAuthManager(
                $app->make(ClientDetector::class),
                $app->make(CookieManager::class),
                $app->make(DeviceManager::class),
                $app->make(TwoFactorManager::class)
            );
        });

        $this->app->alias('omni.auth', OmniAuthManager::class);
    }

    /**
     * Bootstrap package services.
     */
    public function boot(): void
    {
        // Load package database migrations
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/omni-auth.php' => config_path('omni-auth.php'),
            ], 'omni-auth-config');

            $this->publishes([
                __DIR__ . '/../database/migrations/' => database_path('migrations'),
            ], 'omni-auth-migrations');
        }

        // Register Sanctum access token retrieval callback to natively check bearer header & HttpOnly cookies
        if (class_exists(Sanctum::class)) {
            Sanctum::getAccessTokenFromRequestUsing(function (Request $request) {
                // 1. If explicit bearer token is present in Authorization header, use it
                $bearer = $request->bearerToken();
                if ($bearer) {
                    return $bearer;
                }

                // 2. Otherwise, seamlessly retrieve from HttpOnly cookie
                $cookieName = config('omni-auth.cookie.name', 'omni_access_token');
                return $request->cookie($cookieName);
            });
        }

        // Register middleware alias
        /** @var Router $router */
        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('omni.auth', OmniAuthenticate::class);

        // Register built-in authentication routes if enabled
        if (config('omni-auth.routes.enabled', true)) {
            $this->registerRoutes();
        }
    }

    /**
     * Register ready-to-use authentication routes.
     */
    protected function registerRoutes(): void
    {
        $prefix = config('omni-auth.routes.prefix', 'api/auth');
        $middleware = config('omni-auth.routes.middleware', ['api']);

        Route::prefix($prefix)
            ->middleware($middleware)
            ->group(function () {
                Route::post('/login', [Http\Controllers\AuthController::class, 'login'])->name('omni.login');
                Route::post('/register', [Http\Controllers\AuthController::class, 'register'])->name('omni.register');
                Route::post('/refresh', [Http\Controllers\AuthController::class, 'refresh'])->name('omni.refresh');
                Route::post('/logout', [Http\Controllers\AuthController::class, 'logout'])->middleware('omni.auth')->name('omni.logout');
                Route::get('/me', [Http\Controllers\AuthController::class, 'me'])->middleware('omni.auth')->name('omni.me');

                // Multi-Device Management routes
                Route::prefix('devices')->middleware('omni.auth')->group(function () {
                    Route::get('/', [Http\Controllers\DeviceController::class, 'index'])->name('omni.devices.index');
                    Route::delete('/{id}', [Http\Controllers\DeviceController::class, 'destroy'])->name('omni.devices.destroy');
                    Route::post('/logout-others', [Http\Controllers\DeviceController::class, 'logoutOthers'])->name('omni.devices.logout_others');
                    Route::post('/fcm', [Http\Controllers\DeviceController::class, 'updateFcm'])->name('omni.devices.fcm');
                });

                // Two-Factor Authentication routes
                Route::prefix('2fa')->group(function () {
                    Route::post('/challenge', [Http\Controllers\TwoFactorController::class, 'challenge'])->name('omni.2fa.challenge');
                    Route::post('/fallback-otp', [Http\Controllers\TwoFactorController::class, 'fallbackOtp'])->name('omni.2fa.fallback_otp');

                    Route::middleware('omni.auth')->group(function () {
                        Route::post('/setup', [Http\Controllers\TwoFactorController::class, 'setup'])->name('omni.2fa.setup');
                        Route::post('/confirm', [Http\Controllers\TwoFactorController::class, 'confirm'])->name('omni.2fa.confirm');
                        Route::post('/recovery-codes', [Http\Controllers\TwoFactorController::class, 'recoveryCodes'])->name('omni.2fa.recovery_codes');
                        Route::post('/disable', [Http\Controllers\TwoFactorController::class, 'disable'])->name('omni.2fa.disable');
                    });
                });

                // Social Authentication & Mobile Native Token Exchange routes
                Route::prefix('social')->group(function () {
                    Route::post('/exchange', [Http\Controllers\SocialAuthController::class, 'exchange'])->name('omni.social.exchange');
                    Route::get('/{provider}/redirect', [Http\Controllers\SocialAuthController::class, 'redirect'])->name('omni.social.redirect');
                    Route::match(['get', 'post'], '/{provider}/callback', [Http\Controllers\SocialAuthController::class, 'callback'])->name('omni.social.callback');

                    Route::middleware('omni.auth')->group(function () {
                        Route::get('/accounts', [Http\Controllers\SocialAuthController::class, 'accounts'])->name('omni.social.accounts');
                        Route::delete('/{provider}', [Http\Controllers\SocialAuthController::class, 'unlink'])->name('omni.social.unlink');
                    });
                });

                // Password Reset routes
                Route::post('/forgot-password', [Http\Controllers\PasswordResetController::class, 'forgotPassword'])->name('omni.password.forgot');
                Route::post('/verify-reset-otp', [Http\Controllers\PasswordResetController::class, 'verifyOtp'])->name('omni.password.verify_otp');
                Route::post('/reset-password', [Http\Controllers\PasswordResetController::class, 'resetPassword'])->name('omni.password.reset');

                // Magic Login Link routes
                Route::post('/magic-link', [Http\Controllers\VerificationController::class, 'sendMagicLink'])->name('omni.magic.send');
                Route::match(['get', 'post'], '/magic-link/verify', [Http\Controllers\VerificationController::class, 'verifyMagicLink'])->name('omni.magic.verify');

                // Email Verification & Account Deletion routes
                Route::middleware('omni.auth')->group(function () {
                    Route::post('/email/resend', [Http\Controllers\VerificationController::class, 'resendEmail'])->name('omni.email.resend');
                    Route::post('/email/verify', [Http\Controllers\VerificationController::class, 'verifyEmail'])->name('omni.email.verify');
                    Route::delete('/account', [Http\Controllers\VerificationController::class, 'deleteAccount'])->name('omni.account.delete');
                });
            });
    }
}
