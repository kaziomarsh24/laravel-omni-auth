<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Tests;

use Illuminate\Support\Facades\Hash;
use KaziOmar\OmniAuth\Models\AuthDevice;
use Laravel\Sanctum\PersonalAccessToken;

class ConsoleCommandsTest extends TestCase
{
    public function test_install_command_executes_successfully(): void
    {
        $this->artisan('omni:install')
            ->expectsOutputToContain('Initializing Laravel OmniAuth installation')
            ->expectsOutputToContain('OmniAuth configuration and migrations have been published successfully')
            ->assertExitCode(0);
    }

    public function test_prune_expired_tokens_command_purges_stale_records(): void
    {
        $user = TestUser::create([
            'name' => 'Prune Target',
            'email' => 'prune@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        // 1. Create an expired token
        $expiredToken = $user->createToken('expired_token', ['access-api'], now()->subDays(2))->accessToken;

        // 2. Create an active token
        $activeToken = $user->createToken('active_token', ['access-api'], now()->addDays(2))->accessToken;

        // 3. Create a stale device session older than 90 days with no active token
        $staleDevice = AuthDevice::create([
            'user_id' => $user->id,
            'device_id' => 'stale_device_xyz',
            'token_id' => null,
            'last_active_at' => now()->subDays(100),
        ]);

        // 4. Create an active device session
        $activeDevice = AuthDevice::create([
            'user_id' => $user->id,
            'device_id' => 'active_device_abc',
            'token_id' => $activeToken->id,
            'last_active_at' => now(),
        ]);

        $this->artisan('omni:prune-tokens', ['--hours' => 24])
            ->expectsOutputToContain('Pruning completed')
            ->assertExitCode(0);

        // Expired token must be deleted
        $this->assertNull(PersonalAccessToken::find($expiredToken->id));

        // Active token must remain intact
        $this->assertNotNull(PersonalAccessToken::find($activeToken->id));

        // Stale device must be deleted
        $this->assertNull(AuthDevice::find($staleDevice->id));

        // Active device must remain intact
        $this->assertNotNull(AuthDevice::find($activeDevice->id));
    }
}
