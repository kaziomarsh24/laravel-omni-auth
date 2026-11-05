<?php

namespace KaziOmar\OmniAuth\Tests;

use Illuminate\Auth\Events\Registered;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use KaziOmar\OmniAuth\Facades\Omni;
use KaziOmar\OmniAuth\Features;

class RegistrationTest extends TestCase
{
    public function test_user_can_register_via_web_client_and_receives_httponly_cookies(): void
    {
        $payload = [
            'name' => 'Alex Vance',
            'email' => 'alex@example.com',
            'password' => 'SecurePass123!',
            'password_confirmation' => 'SecurePass123!',
        ];

        $request = Request::create('/api/register', 'POST', $payload);
        $response = Omni::register($request);

        $this->assertEquals(201, $response->getStatusCode());

        $content = json_decode($response->getContent(), true);
        $this->assertTrue($content['ok']);
        $this->assertEquals('Registered and authenticated successfully.', $content['message']);
        $this->assertEquals('alex@example.com', $content['data']['user']['email']);

        // Web Client: Plain text tokens must NOT be present in JSON body (XSS protection)
        $this->assertArrayNotHasKey('access_token', $content['data']);
        $this->assertArrayNotHasKey('refresh_token', $content['data']);

        // Web Client: Tokens must be delivered via HttpOnly cookies
        $cookies = $response->headers->getCookies();
        $this->assertNotEmpty($cookies);

        $cookieNames = array_map(fn($c) => $c->getName(), $cookies);
        $this->assertContains('omni_access_token', $cookieNames);
        $this->assertContains('omni_refresh_token', $cookieNames);

        // Verify user in database
        $user = TestUser::where('email', 'alex@example.com')->first();
        $this->assertNotNull($user);
        $this->assertEquals('Alex Vance', $user->name);
        $this->assertTrue(Hash::check('SecurePass123!', $user->password));
    }

    public function test_user_can_register_via_mobile_client_and_receives_bearer_tokens(): void
    {
        $payload = [
            'name' => 'Gordon Freeman',
            'email' => 'gordon@blackmesa.com',
            'password' => 'ResonanceCascade456!',
            'password_confirmation' => 'ResonanceCascade456!',
        ];

        $request = Request::create('/api/register', 'POST', $payload, [], [], [
            'HTTP_X_CLIENT_TYPE' => 'mobile',
        ]);

        $response = Omni::register($request);

        $this->assertEquals(201, $response->getStatusCode());

        $content = json_decode($response->getContent(), true);
        $this->assertTrue($content['ok']);
        $this->assertArrayHasKey('access_token', $content['data']);
        $this->assertArrayHasKey('refresh_token', $content['data']);
        $this->assertEquals('Bearer', $content['data']['token_type']);
        $this->assertEquals(900, $content['data']['expires_in']);
        $this->assertEquals('Gordon Freeman', $content['data']['user']['name']);

        // Mobile Client: No cookies should be attached
        $cookies = $response->headers->getCookies();
        $this->assertEmpty($cookies);

        // Verify user exists in database
        $this->assertDatabaseHas('users', ['email' => 'gordon@blackmesa.com']);
    }

    public function test_user_can_register_without_auto_login(): void
    {
        $payload = [
            'name' => 'Barney Calhoun',
            'email' => 'barney@blackmesa.com',
            'password' => 'CatchMeLater123!',
            'password_confirmation' => 'CatchMeLater123!',
        ];

        $response = Omni::register($payload, autoLogin: false);

        $this->assertEquals(201, $response->getStatusCode());

        $content = json_decode($response->getContent(), true);
        $this->assertTrue($content['ok']);
        $this->assertEquals('User registered successfully.', $content['message']);
        $this->assertEquals('Barney Calhoun', $content['data']['user']['name']);

        // No tokens or cookies
        $this->assertArrayNotHasKey('access_token', $content['data']);
        $this->assertEmpty($response->headers->getCookies());
    }

    public function test_dynamic_auto_hydration_persists_custom_arbitrary_fields(): void
    {
        config()->set('omni-auth.registration.allowed_attributes', ['name', 'email', 'phone', 'company']);

        $payload = [
            'name' => 'Eli Vance',
            'email' => 'eli@blackmesa.com',
            'password' => 'WhiteForest789!',
            'phone' => '+1-555-0199',
            'company' => 'Black Mesa East',
        ];

        $response = Omni::register($payload, autoLogin: false);

        $this->assertEquals(201, $response->getStatusCode());

        $user = TestUser::where('email', 'eli@blackmesa.com')->first();
        $this->assertNotNull($user);
        $this->assertEquals('+1-555-0199', $user->phone);
        $this->assertEquals('Black Mesa East', $user->company);
    }

    public function test_registration_with_form_request_protects_against_mass_assignment(): void
    {
        $formRequest = TestRegistrationFormRequest::create('/api/register', 'POST', [
            'name' => 'Malicious Actor',
            'email' => 'attacker@blackmesa.com',
            'password' => 'Password123!',
            'phone' => '+1-999-0000',
            'is_admin' => 1,
        ], [], [], [
            'HTTP_ACCEPT' => 'application/json',
        ]);

        $formRequest->setContainer(app());
        $formRequest->setRedirector(app(\Illuminate\Routing\Redirector::class));

        $response = Omni::register($formRequest, autoLogin: false);

        $this->assertEquals(201, $response->getStatusCode());

        $user = TestUser::where('email', 'attacker@blackmesa.com')->first();
        $this->assertNotNull($user);
        // FormRequest validated only name, email, password, phone — is_admin must NOT be set to true
        $this->assertFalse((bool) $user->is_admin);
    }

    public function test_registration_auto_assigns_default_role(): void
    {
        config(['omni-auth.registration.default_role' => 'member']);

        $payload = [
            'name' => 'Alyx Vance',
            'email' => 'alyx@city17.com',
            'password' => 'GravityGun321!',
        ];

        $response = Omni::register($payload, autoLogin: false);

        $this->assertEquals(201, $response->getStatusCode());

        $user = TestUser::where('email', 'alyx@city17.com')->first();
        $this->assertEquals('member', $user->role);
    }

    public function test_registration_with_explicit_role_override(): void
    {
        config(['omni-auth.registration.default_role' => 'member']);

        $payload = [
            'name' => 'Administrator',
            'email' => 'breen@citadel.com',
            'password' => 'CombineLeader999!',
        ];

        $response = Omni::register($payload, defaultRole: 'director', autoLogin: false);

        $this->assertEquals(201, $response->getStatusCode());

        $user = TestUser::where('email', 'breen@citadel.com')->first();
        $this->assertEquals('director', $user->role);
    }

    public function test_registration_fires_registered_event(): void
    {
        Event::fake([Registered::class]);

        $payload = [
            'name' => 'Judith Mossman',
            'email' => 'mossman@borealis.com',
            'password' => 'ResearchData444!',
        ];

        Omni::register($payload, autoLogin: false);

        Event::assertDispatched(Registered::class, function (Registered $event) {
            return $event->user->email === 'mossman@borealis.com';
        });
    }

    public function test_registration_fails_validation_on_duplicate_email(): void
    {
        TestUser::create([
            'name' => 'Existing User',
            'email' => 'existing@example.com',
            'password' => Hash::make('password123'),
        ]);

        $payload = [
            'name' => 'Duplicate Attempt',
            'email' => 'existing@example.com',
            'password' => 'ValidPassword123!',
            'password_confirmation' => 'ValidPassword123!',
        ];

        $response = Omni::register($payload);

        $this->assertEquals(422, $response->getStatusCode());

        $content = json_decode($response->getContent(), true);
        $this->assertFalse($content['ok']);
        $this->assertArrayHasKey('email', $content['errors']);
    }

    public function test_registration_fails_validation_on_password_confirmation_mismatch(): void
    {
        $payload = [
            'name' => 'Mismatch User',
            'email' => 'mismatch@example.com',
            'password' => 'ValidPassword123!',
            'password_confirmation' => 'WrongPassword!',
        ];

        $response = Omni::register($payload);

        $this->assertEquals(422, $response->getStatusCode());

        $content = json_decode($response->getContent(), true);
        $this->assertFalse($content['ok']);
        $this->assertArrayHasKey('password', $content['errors']);
    }

    public function test_registration_fails_when_feature_is_disabled(): void
    {
        config(['omni-auth.features' => [
            Features::emailAuthentication(),
            Features::dualModeTokens(),
        ]]);

        $payload = [
            'name' => 'Disabled User',
            'email' => 'disabled@example.com',
            'password' => 'ValidPassword123!',
        ];

        $response = Omni::register($payload);

        $this->assertEquals(403, $response->getStatusCode());

        $content = json_decode($response->getContent(), true);
        $this->assertFalse($content['ok']);
        $this->assertEquals('Registration feature is disabled.', $content['message']);
    }

    public function test_registration_via_api_route(): void
    {
        Route::post('/api/auth/register', function (Request $request) {
            return Omni::register($request);
        });

        // Test via standard JSON API post
        $response = $this->postJson('/api/auth/register', [
            'name' => 'API Registered',
            'email' => 'api@example.com',
            'password' => 'SecretPass999!',
            'password_confirmation' => 'SecretPass999!',
        ], [
            'X-Client-Type' => 'mobile',
        ]);

        $response->assertStatus(201)
            ->assertJsonPath('ok', true)
            ->assertJsonPath('data.user.email', 'api@example.com')
            ->assertJsonStructure([
                'ok',
                'message',
                'data' => [
                    'access_token',
                    'refresh_token',
                    'token_type',
                    'expires_in',
                    'user',
                ],
            ]);
    }
}

class TestRegistrationFormRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'name' => 'required|string',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string|min:8',
            'phone' => 'nullable|string',
        ];
    }
}
