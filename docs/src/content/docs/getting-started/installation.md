---
title: Installation
description: Step-by-step setup guide for Laravel OmniAuth.
---

This guide covers installing and configuring Laravel OmniAuth in your Laravel application.

## Prerequisites

- **PHP**: 8.2 or higher
- **Laravel**: 11.0, 12.0, or 13.0
- **Database**: MySQL 8.0+, PostgreSQL 13+, or SQLite 3.35+

---

## 1. Install via Composer

Add the package to your application dependencies:

```bash
composer require kaziomar/laravel-omni-auth
```

---

## 2. Run the Installer Command

Execute the installation command to publish the configuration file and database migrations:

```bash
php artisan omni:install
```

Optional flags:
- `--force`: Overwrite existing configuration and migration files.

---

## 3. Configure the User Model

Add the `HasOmniAuth` trait to your `App\Models\User` model. This automatically registers Sanctum's token engine alongside OmniAuth's device tracking, two-factor authentication, and social account relations:

```php
namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use KaziOmar\OmniAuth\Traits\HasOmniAuth;

class User extends Authenticatable
{
    use HasOmniAuth, HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }
}
```

---

## 4. Run Migrations

:::note[Custom User Models with UUIDs / ULIDs]
If your application uses UUIDs or ULIDs as primary keys on the `User` model (`HasUuids`, `$keyType = 'string'`), update `$table->unsignedBigInteger('user_id')` to `$table->uuid('user_id')` (or `$table->string('user_id')`) in the published migration files before running `php artisan migrate`.
:::

Execute the published migrations to create OmniAuth's tables:

```bash
php artisan migrate
```

This creates the following database tables:
- `personal_access_tokens`: Laravel Sanctum token storage.
- `auth_devices`: Device audit records, platform identifiers, and push notification tokens.
- `auth_two_factor`: Encrypted TOTP secrets and hashed recovery codes.
- `auth_social_accounts`: Linked OAuth identities and provider user IDs.

> **Note on Magic Links & OTPs:** Magic login links and password reset OTPs are stored in your configured Laravel cache store (Redis, Memcached, Database, or File) with automatic cryptographic TTL expiration, requiring no separate database tables.

---

## 5. Configure Scheduled Token Pruning

OmniAuth generates short-lived access tokens and sliding refresh tokens. Expired tokens and stale device records should be pruned regularly.

In Laravel 11/12, register the pruning command in `routes/console.php`:

```php
use Illuminate\Support\Facades\Schedule;

// Prune expired tokens and inactive devices
Schedule::command('omni:prune-tokens --hours=24')->daily();
```

You can also run the command manually:

```bash
php artisan omni:prune-tokens --hours=24
```

---

## Next Steps

With installation complete, review the [Configuration Guide](/laravel-omni-auth/getting-started/configuration/) to set token lifetimes, enable optional feature sets, and configure social login providers.
