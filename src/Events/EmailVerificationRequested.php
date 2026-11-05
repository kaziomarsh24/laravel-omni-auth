<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Queue\SerializesModels;

class EmailVerificationRequested
{
    use SerializesModels;

    public string $signedUrl;

    public function __construct(
        public Authenticatable $user,
        public string $verificationUrl,
        public ?string $otp = null
    ) {
        $this->signedUrl = $verificationUrl;
    }
}
