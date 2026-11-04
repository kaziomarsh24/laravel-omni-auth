<?php

namespace KaziOmar\OmniAuth\Tests;

use KaziOmar\OmniAuth\Models\AuthDevice;
use KaziOmar\OmniAuth\Models\AuthSocialAccount;
use KaziOmar\OmniAuth\Models\AuthTwoFactor;
use KaziOmar\OmniAuth\Traits\HasOmniAuth;
use Laravel\Sanctum\PersonalAccessToken;

class HasOmniAuthTraitTest extends TestCase
{
    /** @test */
    public function it_creates_sanctum_tokens_via_has_omni_auth_trait(): void
    {
        $user = TestUser::create([
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => bcrypt('secret123'),
        ]);

        $token = $user->createToken('test-token');

        $this->assertNotEmpty($token->plainTextToken);
        $this->assertCount(1, $user->tokens);
        $this->assertInstanceOf(PersonalAccessToken::class, $user->tokens->first());
    }

    /** @test */
    public function it_provides_devices_relationship(): void
    {
        $user = TestUser::create([
            'name' => 'Device User',
            'email' => 'device@example.com',
            'password' => bcrypt('secret123'),
        ]);

        $token = $user->createToken('device-token');

        AuthDevice::create([
            'user_id' => $user->id,
            'token_id' => $token->accessToken->id,
            'device_id' => 'device-uuid-123',
            'device_name' => 'MacBook Pro',
            'platform' => 'web',
            'last_active_at' => now(),
        ]);

        $this->assertCount(1, $user->devices);
        $this->assertEquals('device-uuid-123', $user->devices->first()->device_id);
    }

    /** @test */
    public function it_provides_two_factor_relationship_and_helper_method(): void
    {
        $user = TestUser::create([
            'name' => '2FA User',
            'email' => '2fa@example.com',
            'password' => bcrypt('secret123'),
        ]);

        $this->assertNull($user->twoFactor);
        $this->assertFalse($user->hasTwoFactorEnabled());

        // Create unconfirmed 2FA record
        $twoFactor = AuthTwoFactor::create([
            'user_id' => $user->id,
            'secret' => 'SECRET123',
            'confirmed_at' => null,
        ]);

        $user->refresh();
        $this->assertNotNull($user->twoFactor);
        $this->assertFalse($user->hasTwoFactorEnabled());

        // Confirm 2FA
        $twoFactor->update(['confirmed_at' => now()]);
        $user->refresh();
        $this->assertTrue($user->hasTwoFactorEnabled());
    }

    /** @test */
    public function it_provides_social_accounts_relationship(): void
    {
        $user = TestUser::create([
            'name' => 'Social User',
            'email' => 'social@example.com',
            'password' => bcrypt('secret123'),
        ]);

        AuthSocialAccount::create([
            'user_id' => $user->id,
            'provider' => 'google',
            'provider_id' => 'google-sub-123',
            'token' => 'oauth-token',
        ]);

        $this->assertCount(1, $user->socialAccounts);
        $this->assertEquals('google', $user->socialAccounts->first()->provider);
    }
}
