<?php

namespace KaziOmar\OmniAuth\Traits;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use KaziOmar\OmniAuth\Models\AuthDevice;
use KaziOmar\OmniAuth\Models\AuthSocialAccount;
use KaziOmar\OmniAuth\Models\AuthTwoFactor;
use Laravel\Sanctum\HasApiTokens;

/**
 * Trait HasOmniAuth
 *
 * Provides Sanctum token capabilities alongside native Eloquent relationships
 * for OmniAuth devices, two-factor authentication, and connected social accounts.
 *
 * @property-read \Illuminate\Database\Eloquent\Collection<int, AuthDevice> $devices
 * @property-read AuthTwoFactor|null $twoFactor
 * @property-read \Illuminate\Database\Eloquent\Collection<int, AuthSocialAccount> $socialAccounts
 */
trait HasOmniAuth
{
    use HasApiTokens;

    /**
     * Active and historical device sessions associated with this user.
     */
    public function devices(): HasMany
    {
        return $this->hasMany(AuthDevice::class, 'user_id');
    }

    /**
     * Two-factor authentication configuration for this user.
     */
    public function twoFactor(): HasOne
    {
        return $this->hasOne(AuthTwoFactor::class, 'user_id');
    }

    /**
     * Connected third-party OAuth social accounts (Google, Apple, GitHub).
     */
    public function socialAccounts(): HasMany
    {
        return $this->hasMany(AuthSocialAccount::class, 'user_id');
    }

    /**
     * Determine if the user has confirmed and activated Two-Factor Authentication.
     */
    public function hasTwoFactorEnabled(): bool
    {
        return $this->twoFactor !== null && $this->twoFactor->isConfirmed();
    }
}
