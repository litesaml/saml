<?php

namespace Tests;

use Litesaml\Exceptions\SamlException;
use Litesaml\IdentityProviderWrapper;
use Litesaml\Models\Messages\Attribute;
use Litesaml\Models\Messages\AuthnRequest;
use Litesaml\Models\Messages\LogoutRequest;
use Litesaml\Models\Messages\LogoutResponse;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

class IdentityProviderWrapperTest extends TestCase
{
    private function idp(): IdentityProviderWrapper
    {
        return new IdentityProviderWrapper($this->makeIdp());
    }

    #[Test]
    public function can_handle_authn_request(): void
    {
        $request = SymfonyRequest::create(
            uri: '/sso',
            parameters: ['SAMLRequest' => $this->fixture('authn_request')],
        );

        $message = $this->idp()->handleAuthnRequest($request);

        $this->assertInstanceOf(AuthnRequest::class, $message);
        $this->assertEquals('MESSAGE-ID', $message->id);
        $this->assertEquals('https://sp.localhost', $message->issuer);
    }

    #[Test]
    public function handle_authn_request_throws_on_wrong_message_type(): void
    {
        $this->expectException(SamlException::class);

        $request = SymfonyRequest::create(
            uri: '/sso',
            parameters: ['SAMLRequest' => $this->fixture('authn_response')],
        );

        $this->idp()->handleAuthnRequest($request);
    }

    #[Test]
    public function can_send_authn_response(): void
    {
        $attributes = [
            new Attribute(name: 'email', value: 'user@example.com'),
        ];

        $response = $this->idp()->sendAuthnResponse($this->makeSp(), $attributes);

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertStringContainsString('https://sp.localhost/acs', $response->headers->get('Location'));
    }

    #[Test]
    public function can_send_logout_request(): void
    {
        $response = $this->idp()->sendLogoutRequest($this->makeSp());

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertStringContainsString('https://sp.localhost/slo', $response->headers->get('Location'));
    }

    #[Test]
    public function can_send_logout_response(): void
    {
        $response = $this->idp()->sendLogoutResponse($this->makeSp());

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertStringContainsString('https://sp.localhost/slo', $response->headers->get('Location'));
    }

    #[Test]
    public function can_handle_logout_request(): void
    {
        $request = SymfonyRequest::create(
            uri: '/slo',
            parameters: ['SAMLRequest' => $this->fixture('logout_request')],
        );

        $message = $this->idp()->handleLogoutRequest($request);

        $this->assertInstanceOf(LogoutRequest::class, $message);
        $this->assertEquals('LOGOUT-REQUEST-ID', $message->id);
        $this->assertEquals('https://idp.localhost', $message->issuer);
    }

    #[Test]
    public function can_handle_logout_response(): void
    {
        $request = SymfonyRequest::create(
            uri: '/slo',
            parameters: ['SAMLResponse' => $this->fixture('logout_response')],
        );

        $message = $this->idp()->handleLogoutResponse($request);

        $this->assertInstanceOf(LogoutResponse::class, $message);
        $this->assertEquals('LOGOUT-RESPONSE-ID', $message->id);
        $this->assertEquals('https://idp.localhost', $message->issuer);
    }

    #[Test]
    public function validate_signature_returns_false_without_signing_config(): void
    {
        $request = SymfonyRequest::create(
            uri: '/sso',
            parameters: ['SAMLRequest' => $this->fixture('authn_request')],
        );

        $message = $this->idp()->handleAuthnRequest($request);

        $this->assertFalse($this->idp()->validateSignature($message, $this->makeSp()));
    }
}
