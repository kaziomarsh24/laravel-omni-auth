<?php

namespace KaziOmar\OmniAuth\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Queue\SerializesModels;

class EmailVerificationRequested
{
    use SerializesModels;

    public function __construct(
        public Authenticatable $user,
        public string $verificationUrl,
        public ?string $otp = null
    ) {}
}
