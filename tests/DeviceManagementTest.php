<?php

namespace KaziOmar\OmniAuth\Tests;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use KaziOmar\OmniAuth\Facades\Omni;
use KaziOmar\OmniAuth\Features;
use KaziOmar\OmniAuth\Models\AuthDevice;
use Laravel\Sanctum\PersonalAccessToken;

class DeviceManagementTest extends TestCase
{
    protected TestUser $user;

    protected function setUp(): void
    {
        parent::setUp();

        // Enable device tracking and FCM management for these tests
        config(['omni-auth.features' => [
            Features::emailAuthentication(),
            Features::dualModeTokens(),
            Features::tokenRotation(),
            Features::registration(),
            Features::deviceTracking(),
            Features::fcmTokenManagement(),
        ]]);

        $this->user = TestUser::create([
            'name' => 'Device Explorer',
            'email' => 'device@example.com',
            'password' => Hash::make('SecretPass123!'),
        ]);
    }

    public function test_login_automatically_tracks_device_and_fcm_token_when_feature_enabled(): void
    {
        $request = Request::create('/api/auth/login', 'POST', [
            'email' => 'device@example.com',
            'password' => 'SecretPass123!',
        ], [], [], [
            'HTTP_X_CLIENT_TYPE' => 'mobile',
            'HTTP_X_DEVICE_ID' => 'pixel-8-uuid-1234',
            'HTTP_X_DEVICE_NAME' => 'Google Pixel 8',
            'HTTP_X_FCM_TOKEN' => 'fcm_token_abc_xyz',
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (Linux; Android 14; Pixel 8) Mobile Dart/3.0',
            'REMOTE_ADDR' => '203.0.113.195',
        ]);

        $response = Omni::attempt([
            'email' => 'device@example.com',
            'password' => 'SecretPass123!',
        ], $request);

        $this->assertEquals(200, $response->getStatusCode());

        // Verify device record in database
        $device = AuthDevice::where('user_id', $this->user->id)->first();
        $this->assertNotNull($device);
        $this->assertEquals('pixel-8-uuid-1234', $device->device_id);
        $this->assertEquals('Google Pixel 8', $device->device_name);
        $this->assertEquals('android', $device->platform);
        $this->assertEquals('fcm_token_abc_xyz', $device->fcm_token);
        $this->assertEquals('203.0.113.195', $device->ip_address);
        $this->assertNotNull($device->token_id);
        $this->assertNotNull($device->last_active_at);

        // Verify linked token in Sanctum
        $token = PersonalAccessToken::find($device->token_id);
        $this->assertNotNull($token);
    }

    public function test_all_devices_listing_returns_active_devices_with_is_current_device_flag(): void
    {
        // 1. Device A (Phone)
        $reqA = Request::create('/api/login', 'POST', [], [], [], [
            'HTTP_X_DEVICE_ID' => 'dev_phone_1',
            'HTTP_X_DEVICE_NAME' => 'My iPhone 15',
        ]);
        $tokenA = $this->user->createToken('token_a');
        Omni::devices()->track($this->user, $reqA, $tokenA->accessToken, 'fcm_a', 'My iPhone 15');

        // 2. Device B (Laptop)
        $reqB = Request::create('/api/login', 'POST', [], [], [], [
            'HTTP_X_DEVICE_ID' => 'dev_laptop_2',
            'HTTP_X_DEVICE_NAME' => 'MacBook Pro',
        ]);
        $tokenB = $this->user->createToken('token_b');
        Omni::devices()->track($this->user, $reqB, $tokenB->accessToken, null, 'MacBook Pro');

        // Authenticate as Device B (Laptop)
        $this->actingAs($this->user, 'sanctum');

        $devices = Omni::devices()->all($this->user, $reqB);

        $this->assertCount(2, $devices);

        $laptop = $devices->firstWhere('device_id', 'dev_laptop_2');
        $phone = $devices->firstWhere('device_id', 'dev_phone_1');

        $this->assertTrue($laptop['is_current_device'], 'Current device must be marked true.');
        $this->assertFalse($phone['is_current_device'], 'Other device must be marked false.');
    }

    public function test_revoke_specific_device_deletes_device_and_its_sanctum_token(): void
    {
        $req = Request::create('/api/login', 'POST');
        $tokenToRevoke = $this->user->createToken('token_to_revoke');

        $device = Omni::devices()->track($this->user, $req, $tokenToRevoke->accessToken, 'fcm_target', 'Target Device');
        $this->assertNotNull(PersonalAccessToken::find($tokenToRevoke->accessToken->id));

        $revoked = Omni::devices()->revoke($device->id, $this->user);

        $this->assertTrue($revoked);
        $this->assertDatabaseMissing('auth_devices', ['id' => $device->id]);
        $this->assertNull(PersonalAccessToken::find($tokenToRevoke->accessToken->id), 'Sanctum token must be revoked when device is deleted.');
    }

    public function test_logout_others_terminates_all_sessions_except_current_device(): void
    {
        // Setup Current Device
        $currentReq = Request::create('/api/login', 'POST', [], [], [], ['HTTP_X_DEVICE_ID' => 'current_mac']);
        $currentToken = $this->user->createToken('current_token');
        $currentDevice = Omni::devices()->track($this->user, $currentReq, $currentToken->accessToken, null, 'Current Mac');

        // Setup Other Device 1
        $other1Req = Request::create('/api/login', 'POST', [], [], [], ['HTTP_X_DEVICE_ID' => 'other_iphone']);
        $other1Token = $this->user->createToken('other_1_token');
        Omni::devices()->track($this->user, $other1Req, $other1Token->accessToken, 'fcm_1', 'Other iPhone');

        // Setup Other Device 2
        $other2Req = Request::create('/api/login', 'POST', [], [], [], ['HTTP_X_DEVICE_ID' => 'other_tablet']);
        $other2Token = $this->user->createToken('other_2_token');
        Omni::devices()->track($this->user, $other2Req, $other2Token->accessToken, 'fcm_2', 'Other Tablet');

        $this->assertEquals(3, AuthDevice::where('user_id', $this->user->id)->count());

        // Perform logoutOthers
        $revokedCount = Omni::devices()->logoutOthers($this->user, $currentReq);

        $this->assertEquals(2, $revokedCount);
        $this->assertEquals(1, AuthDevice::where('user_id', $this->user->id)->count());

        // Current device must still be present
        $this->assertDatabaseHas('auth_devices', ['id' => $currentDevice->id]);
        $this->assertNotNull(PersonalAccessToken::find($currentToken->accessToken->id));

        // Other devices & tokens must be purged
        $this->assertNull(PersonalAccessToken::find($other1Token->accessToken->id));
        $this->assertNull(PersonalAccessToken::find($other2Token->accessToken->id));
    }

    public function test_fcm_token_and_device_are_cleaned_up_on_logout(): void
    {
        $loginReq = Request::create('/api/auth/login', 'POST', [], [], [], [
            'HTTP_X_DEVICE_ID' => 'clean_device_id',
            'HTTP_X_FCM_TOKEN' => 'active_fcm_token_123',
        ]);
        $token = $this->user->createToken('clean_token');
        Omni::devices()->track($this->user, $loginReq, $token->accessToken, 'active_fcm_token_123', 'Clean Device');

        $this->assertDatabaseHas('auth_devices', [
            'device_id' => 'clean_device_id',
            'fcm_token' => 'active_fcm_token_123',
        ]);

        $this->actingAs($this->user, 'sanctum');

        // User logs out
        $logoutReq = Request::create('/api/auth/logout', 'POST', [], [], [], [
            'HTTP_X_DEVICE_ID' => 'clean_device_id',
        ]);
        $response = Omni::logout($logoutReq);
        $this->assertEquals(200, $response->getStatusCode());

        // Device record must be purged from database to prevent misdirected push notifications
        $this->assertDatabaseMissing('auth_devices', ['device_id' => 'clean_device_id']);
    }

    public function test_device_routes_via_api(): void
    {
        $token = $this->user->createToken('api_device_token');
        $req = Request::create('/api/auth/devices', 'GET', [], [], [], ['HTTP_X_DEVICE_ID' => 'api_phone']);
        $device = Omni::devices()->track($this->user, $req, $token->accessToken, 'old_fcm', 'My API Phone');

        // 1. GET /api/auth/devices
        $listResponse = $this->getJson('/api/auth/devices', [
            'Authorization' => "Bearer {$token->plainTextToken}",
            'X-Device-ID' => 'api_phone',
        ]);

        $listResponse->assertStatus(200)
            ->assertJsonPath('ok', true)
            ->assertJsonPath('data.devices.0.device_id', 'api_phone');

        // 2. POST /api/auth/devices/fcm (update FCM token)
        $fcmResponse = $this->postJson('/api/auth/devices/fcm', [
            'fcm_token' => 'updated_fcm_token_999',
        ], [
            'Authorization' => "Bearer {$token->plainTextToken}",
            'X-Device-ID' => 'api_phone',
        ]);

        $fcmResponse->assertStatus(200)
            ->assertJsonPath('ok', true)
            ->assertJsonPath('data.device.fcm_token', 'updated_fcm_token_999');

        $this->assertDatabaseHas('auth_devices', [
            'device_id' => 'api_phone',
            'fcm_token' => 'updated_fcm_token_999',
        ]);

        // 3. DELETE /api/auth/devices/{id}
        $deleteResponse = $this->deleteJson("/api/auth/devices/{$device->id}", [], [
            'Authorization' => "Bearer {$token->plainTextToken}",
        ]);

        $deleteResponse->assertStatus(200)
            ->assertJsonPath('ok', true);

        $this->assertDatabaseMissing('auth_devices', ['id' => $device->id]);
    }

    public function test_device_routes_return_403_when_feature_is_disabled(): void
    {
        config(['omni-auth.features' => [
            Features::emailAuthentication(),
            Features::dualModeTokens(),
        ]]);

        $token = $this->user->createToken('disabled_feature_token');

        $response = $this->getJson('/api/auth/devices', [
            'Authorization' => "Bearer {$token->plainTextToken}",
        ]);

        $response->assertStatus(403)
            ->assertJsonPath('ok', false)
            ->assertJsonPath('message', 'Device tracking feature is disabled.');
    }
}
