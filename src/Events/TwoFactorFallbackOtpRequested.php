<?php

namespace KaziOmar\OmniAuth\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Queue\SerializesModels;

class TwoFactorFallbackOtpRequested
{
    use SerializesModels;

    public function __construct(
        public Authenticatable $user,
        public string $otp
    ) {}
}
