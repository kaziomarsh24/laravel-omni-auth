<?php

namespace KaziOmar\OmniAuth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AuthTwoFactor extends Model
{
    protected $table = 'auth_two_factor';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'secret' => 'encrypted',
            'recovery_codes' => 'array',
            'confirmed_at' => 'datetime',
        ];
    }

    /**
     * Check if 2FA has been confirmed and is actively enforced.
     */
    public function isConfirmed(): bool
    {
        return $this->confirmed_at !== null;
    }

    /**
     * The user this two-factor authentication configuration belongs to.
     */
    public function user(): BelongsTo
    {
        $userModel = config('omni-auth.user_model', 'App\\Models\\User');

        return $this->belongsTo($userModel, 'user_id');
    }
}
