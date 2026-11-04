<?php

namespace KaziOmar\OmniAuth\Tests;

use Illuminate\Auth\Events\Registered;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use KaziOmar\OmniAuth\Facades\Omni;
use KaziOmar\OmniAuth\Models\AuthSocialAccount;

class SocialAuthTest extends TestCase
{
    protected TestUser $user;

    protected function setUp(): void
    {
        parent::setUp();

        $this->user = TestUser::create([
            'name' => 'Existing User',
            'email' => 'existing@example.com',
            'password' => Hash::make('Password123!'),
        ]);

        config()->set('omni-auth.social.providers.google', [
            'client_id' => 'google-client-id-123.apps.googleusercontent.com',
            'client_secret' => 'google-secret-xyz',
            'redirect' => 'http://localhost/api/auth/social/google/callback',
            'mobile_client_ids' => ['google-mobile-client-id-456.apps.googleusercontent.com'],
        ]);

        config()->set('omni-auth.social.providers.apple', [
            'client_id' => 'com.example.service',
            'team_id' => 'TEAM123456',
            'key_id' => 'KEY123456',
            'redirect' => 'http://localhost/api/auth/social/apple/callback',
        ]);
    }

    public function test_oauth_redirect_url_generation(): void
    {
        $googleUrl = Omni::social()->getRedirectUrl('google');
        $this->assertStringContainsString('accounts.google.com/o/oauth2/v2/auth', $googleUrl);
        $this->assertStringContainsString('google-client-id-123', $googleUrl);

        $appleUrl = Omni::social()->getRedirectUrl('apple');
        $this->assertStringContainsString('appleid.apple.com/auth/authorize', $appleUrl);
        $this->assertStringContainsString('com.example.service', $appleUrl);

        $response = $this->getJson('/api/auth/social/google/redirect');
        $response->assertStatus(200)
            ->assertJsonPath('ok', true);
        $this->assertStringContainsString('accounts.google.com', $response->json('redirect_url'));
    }

    public function test_mobile_google_token_exchange_creates_new_user(): void
    {
        Event::fake([Registered::class]);

        Http::fake([
            'https://oauth2.googleapis.com/tokeninfo*' => Http::response([
                'sub' => 'google_sub_999888',
                'email' => 'newgoogleuser@example.com',
                'email_verified' => 'true',
                'name' => 'Google Newbie',
                'picture' => 'https://example.com/avatar.jpg',
                'aud' => 'google-client-id-123.apps.googleusercontent.com',
                'exp' => time() + 3600,
            ], 200),
        ]);

        $response = $this->postJson('/api/auth/social/exchange', [
            'provider' => 'google',
            'id_token' => 'mock_google_id_token',
        ], [
            'X-Client-Type' => 'mobile',
        ]);

        $response->assertStatus(200)
            ->assertJsonPath('ok', true)
            ->assertJsonPath('data.user.email', 'newgoogleuser@example.com')
            ->assertJsonPath('data.user.name', 'Google Newbie');

        $this->assertArrayHasKey('access_token', $response->json('data'));

        // Verify database records
        $newUser = TestUser::where('email', 'newgoogleuser@example.com')->first();
        $this->assertNotNull($newUser);
        $this->assertNotNull($newUser->email_verified_at);

        $socialAccount = AuthSocialAccount::where('provider', 'google')
            ->where('provider_id', 'google_sub_999888')
            ->first();
        $this->assertNotNull($socialAccount);
        $this->assertEquals($newUser->id, $socialAccount->user_id);
        $this->assertEquals('https://example.com/avatar.jpg', $socialAccount->avatar);

        Event::assertDispatched(Registered::class);
    }

    public function test_mobile_google_token_exchange_performs_intelligent_account_linking(): void
    {
        // $this->user already has email 'existing@example.com' but no social accounts linked
        $this->assertNull($this->user->email_verified_at);

        Http::fake([
            'https://oauth2.googleapis.com/tokeninfo*' => Http::response([
                'sub' => 'google_sub_existing_111',
                'email' => 'existing@example.com',
                'email_verified' => 'true',
                'name' => 'Existing User (Google)',
                'aud' => 'google-mobile-client-id-456.apps.googleusercontent.com',
                'exp' => time() + 3600,
            ], 200),
        ]);

        $response = $this->postJson('/api/auth/social/exchange', [
            'provider' => 'google',
            'id_token' => 'mock_google_id_token_existing',
        ], [
            'X-Client-Type' => 'mobile',
        ]);

        $response->assertStatus(200)
            ->assertJsonPath('ok', true)
            ->assertJsonPath('data.user.id', $this->user->id);

        // Assert no duplicate user was created
        $this->assertEquals(1, TestUser::where('email', 'existing@example.com')->count());

        // Assert social account is linked
        $social = AuthSocialAccount::where('provider', 'google')
            ->where('provider_id', 'google_sub_existing_111')
            ->first();
        $this->assertNotNull($social);
        $this->assertEquals($this->user->id, $social->user_id);

        // Assert email_verified_at was auto-updated since Google verified it
        $this->user->refresh();
        $this->assertNotNull($this->user->email_verified_at);
    }

    public function test_mobile_apple_identity_token_exchange_flow(): void
    {
        // Generate real RSA key pair for testing Apple cryptographic verification
        $rsaKey = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        $details = openssl_pkey_get_details($rsaKey);
        config()->set('omni-auth.social.providers.apple.public_key', $details['key']);

        // Build valid RS256 Apple identity token (JWT)
        $header = ['alg' => 'RS256', 'kid' => 'apple_kid'];
        $claims = [
            'iss' => 'https://appleid.apple.com',
            'aud' => 'com.example.service',
            'exp' => time() + 3600,
            'iat' => time(),
            'sub' => 'apple_sub_777666',
            'email' => 'apple_privaterelay@privaterelay.appleid.com',
            'email_verified' => 'true',
        ];

        $headerEncoded = Omni::social()->base64UrlEncode(json_encode($header));
        $claimsEncoded = Omni::social()->base64UrlEncode(json_encode($claims));
        $dataToSign = "{$headerEncoded}.{$claimsEncoded}";

        openssl_sign($dataToSign, $rawSignature, $rsaKey, OPENSSL_ALGO_SHA256);
        $signatureEncoded = Omni::social()->base64UrlEncode($rawSignature);

        $jwt = "{$dataToSign}.{$signatureEncoded}";

        $response = $this->postJson('/api/auth/social/exchange', [
            'provider' => 'apple',
            'id_token' => $jwt,
            'user' => [
                'name' => [
                    'firstName' => 'Steve',
                    'lastName' => 'Jobs',
                ],
            ],
        ], [
            'X-Client-Type' => 'mobile',
        ]);

        $response->assertStatus(200)
            ->assertJsonPath('ok', true)
            ->assertJsonPath('data.user.email', 'apple_privaterelay@privaterelay.appleid.com')
            ->assertJsonPath('data.user.name', 'Steve Jobs');

        $social = AuthSocialAccount::where('provider', 'apple')
            ->where('provider_id', 'apple_sub_777666')
            ->first();
        $this->assertNotNull($social);
        $this->assertEquals('apple_privaterelay@privaterelay.appleid.com', $social->user->email);
    }

    public function test_apple_client_secret_jwt_generation(): void
    {
        // Generate real EC key for test
        $ecKey = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        openssl_pkey_export($ecKey, $pem);

        config()->set('omni-auth.social.providers.apple.private_key', $pem);

        $clientSecret = Omni::social()->generateAppleClientSecret();
        $this->assertNotEmpty($clientSecret);

        $parts = explode('.', $clientSecret);
        $this->assertCount(3, $parts);

        $header = json_decode(Omni::social()->base64UrlDecode($parts[0]), true);
        $this->assertEquals('ES256', $header['alg']);
        $this->assertEquals('KEY123456', $header['kid']);

        $payload = json_decode(Omni::social()->base64UrlDecode($parts[1]), true);
        $this->assertEquals('TEAM123456', $payload['iss']);
        $this->assertEquals('com.example.service', $payload['sub']);
        $this->assertEquals('https://appleid.apple.com', $payload['aud']);
    }

    public function test_linked_accounts_listing_and_safe_unlinking(): void
    {
        // Link 2 accounts to existing user
        AuthSocialAccount::create([
            'user_id' => $this->user->id,
            'provider' => 'google',
            'provider_id' => 'google_sub_user_1',
            'avatar' => 'https://example.com/avatar1.png',
        ]);

        AuthSocialAccount::create([
            'user_id' => $this->user->id,
            'provider' => 'apple',
            'provider_id' => 'apple_sub_user_2',
        ]);

        // 1. List accounts
        $this->actingAs($this->user);
        $listRes = $this->getJson('/api/auth/social/accounts');
        $listRes->assertStatus(200)
            ->assertJsonPath('ok', true);

        $accounts = $listRes->json('data.accounts');
        $this->assertCount(2, $accounts);

        // 2. Unlink google account
        $unlinkRes = $this->deleteJson('/api/auth/social/google');
        $unlinkRes->assertStatus(200)
            ->assertJsonPath('ok', true);

        $this->assertDatabaseMissing('auth_social_accounts', [
            'user_id' => $this->user->id,
            'provider' => 'google',
        ]);

        // 3. Test lockout protection: create a social-only user with no password
        $socialOnlyUser = TestUser::create([
            'name' => 'Social Only',
            'email' => 'socialonly@example.com',
            'password' => '', // No password set
        ]);

        AuthSocialAccount::create([
            'user_id' => $socialOnlyUser->id,
            'provider' => 'github',
            'provider_id' => 'gh_12345',
        ]);

        $this->actingAs($socialOnlyUser);

        // Attempting to unlink the only authentication method without password must be rejected
        $lockoutRes = $this->deleteJson('/api/auth/social/github');
        $lockoutRes->assertStatus(400)
            ->assertJsonPath('ok', false);

        $this->assertDatabaseHas('auth_social_accounts', [
            'user_id' => $socialOnlyUser->id,
            'provider' => 'github',
        ]);
    }
}
