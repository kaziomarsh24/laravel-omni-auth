<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Queue\SerializesModels;

class TwoFactorEnabled
{
    use SerializesModels;

    public function __construct(
        public Authenticatable $user
    ) {}
}
