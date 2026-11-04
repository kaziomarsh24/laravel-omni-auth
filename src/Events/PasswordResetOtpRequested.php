<?php

namespace KaziOmar\OmniAuth\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Queue\SerializesModels;

class PasswordResetOtpRequested
{
    use SerializesModels;

    public function __construct(
        public Authenticatable $user,
        public string $otp,
        public ?string $resetUrl = null
    ) {}
}
