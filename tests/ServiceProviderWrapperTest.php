<?php

namespace Tests;

use Litesaml\Enums\BindingType;
use Litesaml\Enums\Status;
use Litesaml\Exceptions\SamlException;
use Litesaml\Models\Descriptors\Idp;
use Litesaml\Models\Messages\AuthnRequest;
use Litesaml\Models\Messages\AuthnResponse;
use Litesaml\Models\Messages\LogoutRequest;
use Litesaml\Models\Messages\LogoutResponse;
use Litesaml\ServiceProviderWrapper;
use PHPUnit\Framework\Attributes\Test;

class ServiceProviderWrapperTest extends TestCase
{
    #[Test]
    public function can_parse_metadata(): void
    {
        $xml = file_get_contents(__DIR__ . '/fixtures/idp_metadata.xml');

        $idp = ServiceProviderWrapper::parseMetadata($xml);

        $this->assertInstanceOf(Idp::class, $idp);
        $this->assertEquals('https://idp.localhost', $idp->entityId);
        $this->assertEquals('https://idp.localhost/sso', $idp->sso->location);
        $this->assertEquals(BindingType::REDIRECT, $idp->sso->binding);
        $this->assertEquals('https://idp.localhost/slo', $idp->slo->location);
        $this->assertNotNull($idp->signing);
    }

    #[Test]
    public function parse_metadata_throws_without_idp_descriptor(): void
    {
        $this->expectException(SamlException::class);

        ServiceProviderWrapper::parseMetadata('<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"/>');
    }

    #[Test]
    public function can_generate_metadata(): void
    {
        $xml = $this->makeSpWrapper()->generateMetadata();

        $this->assertStringContainsString('EntityDescriptor', $xml);
        $this->assertStringContainsString('https://sp.localhost', $xml);
        $this->assertStringContainsString('SPSSODescriptor', $xml);
        $this->assertStringContainsString('AssertionConsumerService', $xml);
        $this->assertStringContainsString('SingleLogoutService', $xml);
    }

    #[Test]
    public function generate_metadata_includes_key_descriptor_when_signing_configured(): void
    {
        $xml = $this->makeSpWrapper($this->makeSpWithSigning())->generateMetadata();

        $this->assertStringContainsString('KeyDescriptor', $xml);
        $this->assertStringContainsString('use="signing"', $xml);
    }

    #[Test]
    public function can_send_authn_request(): void
    {
        $response = $this->makeSpWrapper()->sendAuthnRequest($this->makeIdp());

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertStringContainsString('https://idp.localhost/sso', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function send_authn_request_includes_relay_state(): void
    {
        $response = $this->makeSpWrapper()->sendAuthnRequest($this->makeIdp(), 'my-relay-state');

        $this->assertStringContainsString('RelayState=my-relay-state', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function can_handle_authn_response(): void
    {
        $request = $this->makePostRequest('/acs', ['SAMLResponse' => $this->fixture('authn_response', deflate: false)]);

        $message = $this->makeSpWrapper()->handleAuthnResponse($request);

        $this->assertInstanceOf(AuthnResponse::class, $message);
        $this->assertEquals('RESPONSE-ID', $message->id);
        $this->assertEquals('https://idp.localhost', $message->issuer);
        $this->assertEquals('user@example.com', $message->getAttributeByName('email')?->value);
        $this->assertNull($message->getAttributeByName('nonexistent'));
        $this->assertEquals(Status::SUCCESS, $message->status);
        $this->assertEquals('user@example.com', $message->nameId);
        $this->assertEquals('REQUEST-ID', $message->inResponseTo);
        $this->assertTrue($message->isSuccess());
    }

    #[Test]
    public function handle_authn_response_throws_on_wrong_message_type(): void
    {
        $this->expectException(SamlException::class);

        $request = $this->makePostRequest('/acs', ['SAMLResponse' => $this->fixture('logout_response', deflate: false)]);

        $this->makeSpWrapper()->handleAuthnResponse($request);
    }

    #[Test]
    public function can_handle_authn_request(): void
    {
        $request = $this->makeGetRequest('/sso', ['SAMLRequest' => $this->fixture('authn_request'), 'RelayState' => 'my-relay-state']);

        $message = $this->makeSpWrapper()->handleAuthnRequest($request);

        $this->assertInstanceOf(AuthnRequest::class, $message);
        $this->assertEquals('MESSAGE-ID', $message->id);
        $this->assertEquals('https://sp.localhost', $message->issuer);
        $this->assertEquals('my-relay-state', $message->relayState);
    }

    #[Test]
    public function can_send_logout_request(): void
    {
        $response = $this->makeSpWrapper()->sendLogoutRequest($this->makeIdp(), 'user@example.com');

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertStringContainsString('https://idp.localhost/slo', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function send_logout_request_includes_relay_state(): void
    {
        $response = $this->makeSpWrapper()->sendLogoutRequest($this->makeIdp(), 'user@example.com', 'my-relay-state');

        $this->assertStringContainsString('RelayState=my-relay-state', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function can_send_logout_response(): void
    {
        $response = $this->makeSpWrapper()->sendLogoutResponse($this->makeIdp());

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertStringContainsString('https://idp.localhost/slo', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function can_handle_logout_request(): void
    {
        $request = $this->makeGetRequest('/slo', ['SAMLRequest' => $this->fixture('logout_request')]);

        $message = $this->makeSpWrapper()->handleLogoutRequest($request);

        $this->assertInstanceOf(LogoutRequest::class, $message);
        $this->assertEquals('LOGOUT-REQUEST-ID', $message->id);
        $this->assertEquals('https://idp.localhost', $message->issuer);
    }

    #[Test]
    public function can_handle_logout_response(): void
    {
        $request = $this->makeGetRequest('/slo', ['SAMLResponse' => $this->fixture('logout_response')]);

        $message = $this->makeSpWrapper()->handleLogoutResponse($request);

        $this->assertInstanceOf(LogoutResponse::class, $message);
        $this->assertEquals('LOGOUT-RESPONSE-ID', $message->id);
        $this->assertEquals('https://idp.localhost', $message->issuer);
    }

    #[Test]
    public function validate_signature_returns_false_without_signing_config(): void
    {
        $request = $this->makePostRequest('/acs', ['SAMLResponse' => $this->fixture('authn_response', deflate: false)]);

        $message = $this->makeSpWrapper()->handleAuthnResponse($request);

        $this->assertFalse($this->makeSpWrapper()->validateSignature($message, $this->makeIdp()));
    }

    #[Test]
    public function can_validate_signature(): void
    {
        $spWithSigning = $this->makeSpWrapper($this->makeSpWithSigning());

        $redirectResponse = $spWithSigning->sendAuthnRequest($this->makeIdp());
        $location = $redirectResponse->getHeaderLine('Location');

        parse_str((string) parse_url($location, PHP_URL_QUERY), $queryParams);
        $request = $this->makeGetRequest($location, $queryParams);

        $idp = $this->makeIdpWrapper();
        $message = $idp->handleAuthnRequest($request);

        $this->assertTrue($spWithSigning->validateSignature($message, $this->makeSpWithSigning()));
    }
}
