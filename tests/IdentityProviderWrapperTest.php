<?php

namespace Tests;

use Litesaml\Exceptions\SamlException;
use Litesaml\Models\Messages\Attribute;
use Litesaml\Models\Messages\AuthnRequest;
use Litesaml\Models\Messages\LogoutRequest;
use Litesaml\Models\Messages\LogoutResponse;
use PHPUnit\Framework\Attributes\Test;

class IdentityProviderWrapperTest extends TestCase
{
    #[Test]
    public function can_handle_authn_request(): void
    {
        $request = $this->makeGetRequest('/sso', ['SAMLRequest' => $this->fixture('authn_request')]);

        $message = $this->makeIdpWrapper()->handleAuthnRequest($request);

        $this->assertInstanceOf(AuthnRequest::class, $message);
        $this->assertEquals('MESSAGE-ID', $message->id);
        $this->assertEquals('https://sp.localhost', $message->issuer);
    }

    #[Test]
    public function handle_authn_request_throws_on_wrong_message_type(): void
    {
        $this->expectException(SamlException::class);

        $request = $this->makeGetRequest('/sso', ['SAMLRequest' => $this->fixture('authn_response')]);

        $this->makeIdpWrapper()->handleAuthnRequest($request);
    }

    #[Test]
    public function can_send_authn_response(): void
    {
        $attributes = [
            new Attribute(name: 'email', value: 'user@example.com'),
        ];

        $response = $this->makeIdpWrapper()->sendAuthnResponse($this->makeSp(), $attributes);

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertStringContainsString('https://sp.localhost/acs', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function can_send_logout_request(): void
    {
        $response = $this->makeIdpWrapper()->sendLogoutRequest($this->makeSp(), 'user@example.com');

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertStringContainsString('https://sp.localhost/slo', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function can_send_logout_response(): void
    {
        $response = $this->makeIdpWrapper()->sendLogoutResponse($this->makeSp());

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertStringContainsString('https://sp.localhost/slo', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function can_handle_logout_request(): void
    {
        $request = $this->makeGetRequest('/slo', ['SAMLRequest' => $this->fixture('logout_request')]);

        $message = $this->makeIdpWrapper()->handleLogoutRequest($request);

        $this->assertInstanceOf(LogoutRequest::class, $message);
        $this->assertEquals('LOGOUT-REQUEST-ID', $message->id);
        $this->assertEquals('https://idp.localhost', $message->issuer);
    }

    #[Test]
    public function can_handle_logout_response(): void
    {
        $request = $this->makeGetRequest('/slo', ['SAMLResponse' => $this->fixture('logout_response')]);

        $message = $this->makeIdpWrapper()->handleLogoutResponse($request);

        $this->assertInstanceOf(LogoutResponse::class, $message);
        $this->assertEquals('LOGOUT-RESPONSE-ID', $message->id);
        $this->assertEquals('https://idp.localhost', $message->issuer);
    }

    #[Test]
    public function validate_signature_returns_false_without_signing_config(): void
    {
        $request = $this->makeGetRequest('/sso', ['SAMLRequest' => $this->fixture('authn_request')]);

        $message = $this->makeIdpWrapper()->handleAuthnRequest($request);

        $this->assertFalse($this->makeIdpWrapper()->validateSignature($message, $this->makeSp()));
    }
}
