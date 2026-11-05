<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Queue\SerializesModels;

class PasswordResetOtpRequested
{
    use SerializesModels;

    public ?string $signedUrl = null;

    public function __construct(
        public Authenticatable $user,
        public string $otp,
        public ?string $resetUrl = null
    ) {
        $this->signedUrl = $resetUrl;
    }
}
