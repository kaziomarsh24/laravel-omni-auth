<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Tests;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Hash;
use KaziOmar\OmniAuth\Facades\Omni;
use KaziOmar\OmniAuth\Models\AuthDevice;
use KaziOmar\OmniAuth\Models\AuthTwoFactor;
use Laravel\Sanctum\PersonalAccessToken;

class RedTeamFixesTest extends TestCase
{
    private const MOBILE_HEADER = ['X-Client-Type' => 'mobile'];

    public function test_registration_additional_data_cannot_override_guarded_keys(): void
    {
        $response = Omni::register([
            'name' => 'Attacker User',
            'email' => 'attacker@example.com',
            'password' => 'SecurePass123!',
            'password_confirmation' => 'SecurePass123!',
        ], [
            'is_admin' => true,
            'role' => 'superadmin',
            'company' => 'Safe Company',
        ]);

        $this->assertEquals(201, $response->getStatusCode());
        $user = TestUser::where('email', 'attacker@example.com')->first();
        $this->assertNotNull($user);

        // Guarded keys MUST not be escalated
        $this->assertFalse((bool) $user->is_admin);
        $this->assertNull($user->role);

        // Safe additional keys MUST be preserved
        $this->assertEquals('Safe Company', $user->company);
    }

    public function test_prune_expired_tokens_command_cleans_orphaned_devices_with_deleted_tokens(): void
    {
        $user = TestUser::create([
            'name' => 'Orphan Device User',
            'email' => 'orphan@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        // Stale device with token_id that points to a non-existent/deleted token
        AuthDevice::create([
            'user_id' => $user->id,
            'device_id' => 'dev_orphaned_999',
            'token_id' => 999999, // Non-existent token ID
            'last_active_at' => now()->subDays(100),
        ]);

        // Active device that shouldn't be deleted
        AuthDevice::create([
            'user_id' => $user->id,
            'device_id' => 'dev_active_123',
            'token_id' => 999998,
            'last_active_at' => now()->subDays(10),
        ]);

        $this->artisan('omni:prune-tokens --hours=24')
            ->assertExitCode(0);

        // Orphaned device older than 90 days MUST be deleted
        $this->assertDatabaseMissing('auth_devices', ['device_id' => 'dev_orphaned_999']);
        // Active device MUST still exist
        $this->assertDatabaseHas('auth_devices', ['device_id' => 'dev_active_123']);
    }

    public function test_recovery_code_is_consumed_atomically(): void
    {
        $user = TestUser::create([
            'name' => '2FA Lock User',
            'email' => 'twofa_lock@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        $twoFactor = AuthTwoFactor::create([
            'user_id' => $user->id,
            'secret' => 'JBSWY3DPEHPK3PXP',
            'recovery_codes' => [
                Hash::make('CODE-1111'),
                Hash::make('CODE-2222'),
            ],
            'confirmed_at' => now(),
        ]);

        $success = Omni::twoFactor()->verifyAndConsumeRecoveryCode($twoFactor, 'CODE-1111');
        $this->assertTrue($success);

        // Fresh check - code MUST be consumed
        $twoFactor->refresh();
        $this->assertCount(1, $twoFactor->recovery_codes);

        // Reusing same code MUST fail
        $secondAttempt = Omni::twoFactor()->verifyAndConsumeRecoveryCode($twoFactor, 'CODE-1111');
        $this->assertFalse($secondAttempt);
    }

    public function test_device_id_sanitization_enforces_length_and_characters(): void
    {
        $user = TestUser::create([
            'name' => 'Device Sanitize User',
            'email' => 'dev_san@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        // Long or weird device ID with malicious SQL-like characters
        $maliciousDeviceId = "dev_' OR '1'='1_" . str_repeat('A', 200);

        $request = Request::create('/api/auth/login', 'POST', [], [], [], [
            'HTTP_X_DEVICE_ID' => $maliciousDeviceId,
        ]);

        $device = Omni::devices()->track($user, $request);

        // System MUST reject malicious device_id and fallback to safe deterministic fingerprint
        $this->assertNotEquals($maliciousDeviceId, $device->device_id);
        $this->assertStringStartsWith('dev_', $device->device_id);
        $this->assertLessThanOrEqual(64, strlen($device->device_id));
    }

    public function test_concurrent_refresh_returns_429_when_locked(): void
    {
        $user = TestUser::create([
            'name' => 'Refresh Lock User',
            'email' => 'reflock@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        $plainRefreshToken = 'mock_refresh_token_string_123';
        $tokenHash = hash('sha256', $plainRefreshToken);

        // Simulate an ongoing concurrent refresh acquiring lock
        $store = config('omni-auth.cache_store');
        $cache = $store ? Cache::store($store) : Cache::store();
        $lock = $cache->lock('omni_refresh_lock:' . $tokenHash, 10);
        $lock->get();

        $request = Request::create('/api/auth/refresh', 'POST', [
            'refresh_token' => $plainRefreshToken,
        ]);

        $response = Omni::refresh($request);

        // MUST return 429 Too Many Requests
        $this->assertEquals(429, $response->getStatusCode());
        $this->assertStringContainsString('Concurrent refresh in progress', $response->getData(true)['message']);

        $lock->release();
    }
}
