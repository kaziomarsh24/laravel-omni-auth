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
        $this->ensureOpenSslConfig();

        parent::setUp();

        $this->setUpDatabase();
    }

    /**
     * Ensure OpenSSL has a valid configuration file on Windows / Laragon / XAMPP.
     */
    protected function ensureOpenSslConfig(): void
    {
        $opensslConf = getenv('OPENSSL_CONF') ?: ($_ENV['OPENSSL_CONF'] ?? null);
        if ($opensslConf && file_exists($opensslConf)) {
            return;
        }

        $candidatePaths = [
            dirname(PHP_BINARY) . '/extras/ssl/openssl.cnf',
            dirname(PHP_BINARY) . '/openssl.cnf',
            'C:\\laragon\\etc\\ssl\\openssl.cnf',
            'C:\\xampp\\php\\extras\\ssl\\openssl.cnf',
        ];

        foreach ($candidatePaths as $candidate) {
            if (file_exists($candidate)) {
                putenv("OPENSSL_CONF={$candidate}");
                $_ENV['OPENSSL_CONF'] = $candidate;
                return;
            }
        }

        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            $fallbackPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'omni_test_openssl.cnf';
            if (!file_exists($fallbackPath)) {
                $minimalConf = "[req]\ndefault_bits = 2048\ndistinguished_name = req_distinguished_name\n[req_distinguished_name]\n";
                file_put_contents($fallbackPath, $minimalConf);
            }
            putenv("OPENSSL_CONF={$fallbackPath}");
            $_ENV['OPENSSL_CONF'] = $fallbackPath;
        }
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
            \KaziOmar\OmniAuth\Features::magicLoginLink(),
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

        // 6. Run add_refresh_token_id migration
        $refreshTokenMigration = require __DIR__ . '/../database/migrations/2026_01_01_000004_add_refresh_token_id_to_auth_devices_table.php';
        $refreshTokenMigration->up();

        // 7. Run add_password_set_at migration
        $passwordSetAtMigration = require __DIR__ . '/../database/migrations/2026_01_01_000005_add_password_set_at_to_users_table.php';
        $passwordSetAtMigration->up();
    }
}

class TestUser extends Authenticatable implements MustVerifyEmail
{
    use \KaziOmar\OmniAuth\Traits\HasOmniAuth, MustVerifyEmailTrait;

    protected $table = 'users';

    protected $guarded = [];

    protected $hidden = [
        'password',
        'remember_token',
    ];
}
