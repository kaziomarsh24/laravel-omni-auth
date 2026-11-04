<?php

namespace KaziOmar\OmniAuth\Tests;

use Illuminate\Auth\MustVerifyEmail as MustVerifyEmailTrait;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Support\Facades\Schema;
use KaziOmar\OmniAuth\OmniAuthServiceProvider;
use Laravel\Sanctum\HasApiTokens;
use Laravel\Sanctum\SanctumServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpDatabase();
    }

    protected function getPackageProviders($app): array
    {
        return [
            SanctumServiceProvider::class,
            OmniAuthServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:2fl+Ktvkfl+Fuz4Qp/A75G2RTiWVA/ZoKZvp6fiiM10=');
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        $app['config']->set('omni-auth.user_model', TestUser::class);
        $app['config']->set('omni-auth.features', [
            \KaziOmar\OmniAuth\Features::emailAuthentication(),
            \KaziOmar\OmniAuth\Features::dualModeTokens(),
            \KaziOmar\OmniAuth\Features::tokenRotation(),
            \KaziOmar\OmniAuth\Features::registration(),
            \KaziOmar\OmniAuth\Features::passwordReset(),
            \KaziOmar\OmniAuth\Features::deviceTracking(),
            \KaziOmar\OmniAuth\Features::fcmTokenManagement(),
            \KaziOmar\OmniAuth\Features::twoFactorAuth(),
            \KaziOmar\OmniAuth\Features::socialLogin(),
        ]);
    }

    protected function setUpDatabase(): void
    {
        // 1. Create users table
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password');
            $table->string('phone')->nullable();
            $table->string('role')->nullable();
            $table->string('company')->nullable();
            $table->timestamp('email_verified_at')->nullable();
            $table->boolean('is_admin')->default(false);
            $table->rememberToken();
            $table->timestamps();
        });

        // 2. Run Sanctum's personal_access_tokens migration
        $sanctumMigration = require __DIR__ . '/../vendor/laravel/sanctum/database/migrations/2019_12_14_000001_create_personal_access_tokens_table.php';
        $sanctumMigration->up();

        // 3. Run auth_devices migration
        $deviceMigration = require __DIR__ . '/../database/migrations/2026_01_01_000001_create_auth_devices_table.php';
        $deviceMigration->up();

        // 4. Run auth_two_factor migration
        $twoFactorMigration = require __DIR__ . '/../database/migrations/2026_01_01_000002_create_auth_two_factor_table.php';
        $twoFactorMigration->up();

        // 5. Run auth_social_accounts migration
        $socialMigration = require __DIR__ . '/../database/migrations/2026_01_01_000003_create_auth_social_accounts_table.php';
        $socialMigration->up();
    }
}

class TestUser extends Authenticatable implements MustVerifyEmail
{
    use HasApiTokens, MustVerifyEmailTrait;

    protected $table = 'users';

    protected $guarded = [];

    protected $hidden = [
        'password',
        'remember_token',
    ];
}
