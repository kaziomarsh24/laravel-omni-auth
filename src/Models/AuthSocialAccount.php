<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AuthSocialAccount extends Model
{
    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'auth_social_accounts';

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'user_id',
        'provider',
        'provider_id',
        'token',
        'refresh_token',
        'expires_at',
        'avatar',
        'data',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'token' => 'encrypted',
            'refresh_token' => 'encrypted',
            'expires_at' => 'datetime',
            'data' => 'array',
        ];
    }

    /**
     * Get the owner user of this social account.
     */
    public function user(): BelongsTo
    {
        $userModel = config('omni-auth.user_model', 'App\\Models\\User');

        return $this->belongsTo($userModel, 'user_id');
    }
}
