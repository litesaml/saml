<?php

namespace Tests;

use Litesaml\Exceptions\SamlException;
use Litesaml\Models\Messages\AuthnRequest;
use Litesaml\Models\Messages\AuthnResponse;
use Litesaml\Models\Messages\LogoutRequest;
use Litesaml\Models\Messages\LogoutResponse;
use Litesaml\ServiceProviderWrapper;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

class ServiceProviderWrapperTest extends TestCase
{
    private function sp(): ServiceProviderWrapper
    {
        return new ServiceProviderWrapper($this->makeSp());
    }

    #[Test]
    public function can_send_authn_request(): void
    {
        $response = $this->sp()->sendAuthnRequest($this->makeIdp());

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertStringContainsString('https://idp.localhost/sso', $response->headers->get('Location'));
    }

    #[Test]
    public function can_handle_authn_response(): void
    {
        $request = SymfonyRequest::create(
            uri: '/acs',
            method: 'POST',
            parameters: ['SAMLResponse' => $this->fixture('authn_response', deflate: false)],
        );

        $message = $this->sp()->handleAuthnResponse($request);

        $this->assertInstanceOf(AuthnResponse::class, $message);
        $this->assertEquals('RESPONSE-ID', $message->id);
        $this->assertEquals('https://idp.localhost', $message->issuer);
        $this->assertEquals('user@example.com', $message->getAttributeByName('email')?->value);
        $this->assertNull($message->getAttributeByName('nonexistent'));
    }

    #[Test]
    public function handle_authn_response_throws_on_wrong_message_type(): void
    {
        $this->expectException(SamlException::class);

        $request = SymfonyRequest::create(
            uri: '/acs',
            method: 'POST',
            parameters: ['SAMLResponse' => $this->fixture('logout_response', deflate: false)],
        );

        $this->sp()->handleAuthnResponse($request);
    }

    #[Test]
    public function can_handle_authn_request(): void
    {
        $request = SymfonyRequest::create(
            uri: '/sso',
            parameters: ['SAMLRequest' => $this->fixture('authn_request')],
        );

        $message = $this->sp()->handleAuthnRequest($request);

        $this->assertInstanceOf(AuthnRequest::class, $message);
        $this->assertEquals('MESSAGE-ID', $message->id);
        $this->assertEquals('https://sp.localhost', $message->issuer);
    }

    #[Test]
    public function can_send_logout_request(): void
    {
        $response = $this->sp()->sendLogoutRequest($this->makeIdp());

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertStringContainsString('https://idp.localhost/slo', $response->headers->get('Location'));
    }

    #[Test]
    public function can_send_logout_response(): void
    {
        $response = $this->sp()->sendLogoutResponse($this->makeIdp());

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertStringContainsString('https://idp.localhost/slo', $response->headers->get('Location'));
    }

    #[Test]
    public function can_handle_logout_request(): void
    {
        $request = SymfonyRequest::create(
            uri: '/slo',
            parameters: ['SAMLRequest' => $this->fixture('logout_request')],
        );

        $message = $this->sp()->handleLogoutRequest($request);

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

        $message = $this->sp()->handleLogoutResponse($request);

        $this->assertInstanceOf(LogoutResponse::class, $message);
        $this->assertEquals('LOGOUT-RESPONSE-ID', $message->id);
        $this->assertEquals('https://idp.localhost', $message->issuer);
    }

    #[Test]
    public function validate_signature_returns_false_without_signing_config(): void
    {
        $request = SymfonyRequest::create(
            uri: '/acs',
            method: 'POST',
            parameters: ['SAMLResponse' => $this->fixture('authn_response', deflate: false)],
        );

        $message = $this->sp()->handleAuthnResponse($request);

        $this->assertFalse($this->sp()->validateSignature($message, $this->makeIdp()));
    }

    #[Test]
    public function can_validate_signature(): void
    {
        $spWithSigning = new ServiceProviderWrapper($this->makeSpWithSigning());

        $redirectResponse = $spWithSigning->sendAuthnRequest($this->makeIdp());
        $location = $redirectResponse->headers->get('Location');

        $request = SymfonyRequest::create($location);
        $idp = new \Litesaml\IdentityProviderWrapper($this->makeIdp());
        $message = $idp->handleAuthnRequest($request);

        $this->assertTrue($spWithSigning->validateSignature($message, $this->makeSpWithSigning()));
    }
}
