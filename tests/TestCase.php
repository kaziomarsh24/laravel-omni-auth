<?php

namespace KaziOmar\OmniAuth\Tests;

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
    }
}

class TestUser extends Authenticatable
{
    use HasApiTokens;

    protected $table = 'users';

    protected $guarded = [];

    protected $hidden = [
        'password',
        'remember_token',
    ];
}
