<?php

namespace KaziOmar\OmniAuth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Laravel\Sanctum\PersonalAccessToken;

class AuthDevice extends Model
{
    protected $table = 'auth_devices';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'last_active_at' => 'datetime',
        ];
    }

    /**
     * The user this device session belongs to.
     */
    public function user(): BelongsTo
    {
        $userModel = config('omni-auth.user_model', 'App\\Models\\User');

        return $this->belongsTo($userModel, 'user_id');
    }

    /**
     * The Sanctum personal access token linked to this device session.
     */
    public function token(): BelongsTo
    {
        return $this->belongsTo(PersonalAccessToken::class, 'token_id');
    }
}
