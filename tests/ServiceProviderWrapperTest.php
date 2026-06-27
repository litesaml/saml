<?php

namespace Tests;

use Litesaml\Enums\BindingType;
use Litesaml\Enums\Status;
use Litesaml\Exceptions\SamlException;
use Litesaml\Models\Descriptors\Idp;
use Litesaml\Models\Messages\Attribute;
use Litesaml\Models\Messages\AuthnRequest;
use Litesaml\Models\Messages\AuthnResponse;
use Litesaml\Models\Messages\LogoutRequest;
use Litesaml\Models\Messages\LogoutResponse;
use Litesaml\ServiceProviderWrapper;
use PHPUnit\Framework\Attributes\Test;

class ServiceProviderWrapperTest extends TestCase
{
    #[Test]
    public function generate_metadata_includes_encryption_key_descriptor(): void
    {
        $xml = $this->makeSpWrapper($this->makeSpWithEncryption())->generateMetadata();

        $this->assertStringContainsString('use="encryption"', $xml);
    }

    #[Test]
    public function handle_authn_response_decrypts_encrypted_assertions(): void
    {
        $sp = $this->makeSpWithEncryption();
        $attributes = [
            new Attribute(name: 'email', values: ['user@example.com']),
            new Attribute(name: 'roles', values: ['admin'], encrypted: true),
        ];

        $response = $this->makeIdpWrapper()->sendAuthnResponse($sp, $attributes);
        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $params);
        $message = $this->makeSpWrapper($sp)->handleAuthnResponse($this->makeGetRequest('/acs', $params));

        $this->assertInstanceOf(AuthnResponse::class, $message);
        $this->assertEquals(['user@example.com'], $message->getAttributeByName('email')?->values);
        $this->assertFalse($message->getAttributeByName('email')?->encrypted);
        $this->assertEquals(['admin'], $message->getAttributeByName('roles')?->values);
        $this->assertTrue($message->getAttributeByName('roles')?->encrypted);
    }

    #[Test]
    public function handle_authn_response_throws_when_encrypted_assertion_without_sp_encryption_cert(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('No encryption certificate configured to decrypt assertion');

        $sp = $this->makeSpWithEncryption();
        $attributes = [new Attribute(name: 'roles', values: ['admin'], encrypted: true)];
        $response = $this->makeIdpWrapper()->sendAuthnResponse($sp, $attributes);

        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $params);
        $this->makeSpWrapper()->handleAuthnResponse($this->makeGetRequest('/acs', $params));
    }

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
        $this->assertEquals(['user@example.com'], $message->getAttributeByName('email')?->values);
        $this->assertNull($message->getAttributeByName('nonexistent'));
        $this->assertEquals(Status::SUCCESS, $message->status);
        $this->assertEquals('user@example.com', $message->nameId);
        $this->assertEquals('REQUEST-ID', $message->inResponseTo);
        $this->assertTrue($message->isSuccess());
    }

    #[Test]
    public function can_handle_authn_response_with_multi_value_attributes(): void
    {
        $request = $this->makePostRequest('/acs', ['SAMLResponse' => $this->fixture('authn_response_multi_values', deflate: false)]);

        $message = $this->makeSpWrapper()->handleAuthnResponse($request);

        $this->assertEquals(['user@example.com'], $message->getAttributeByName('email')?->values);
        $this->assertEquals(['admin', 'editor', 'viewer'], $message->getAttributeByName('roles')?->values);
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
        $this->assertEquals('user@example.com', $message->nameId);
        $this->assertEquals('SESSION-INDEX-ID', $message->sessionIndex);
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

    #[Test]
    public function handle_authn_response_throws_when_validate_requires_issuer(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('An issuer must be provided to validate the signature');

        $request = $this->makePostRequest('/acs', ['SAMLResponse' => $this->fixture('authn_response', deflate: false)]);
        $this->makeSpWrapper()->handleAuthnResponse($request, validate: true);
    }

    #[Test]
    public function handle_authn_response_throws_on_invalid_signature(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('Invalid signature');

        $request = $this->makePostRequest('/acs', ['SAMLResponse' => $this->fixture('authn_response', deflate: false)]);
        $this->makeSpWrapper()->handleAuthnResponse($request, validate: true, issuer: $this->makeIdp());
    }

    #[Test]
    public function handle_authn_response_validates_signature_when_requested(): void
    {
        $idpWithSigning = $this->makeIdpWrapper($this->makeIdpWithSigning());
        $attributes = [new Attribute(name: 'email', values: ['user@example.com'])];

        $response = $idpWithSigning->sendAuthnResponse($this->makeSp(), $attributes);
        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $params);
        $request = $this->makeGetRequest('/acs', $params);

        $message = $this->makeSpWrapper()->handleAuthnResponse($request, validate: true, issuer: $this->makeIdpWithSigning());

        $this->assertInstanceOf(AuthnResponse::class, $message);
    }

    #[Test]
    public function handle_authn_request_throws_when_validate_requires_issuer(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('An issuer must be provided to validate the signature');

        $request = $this->makeGetRequest('/sso', ['SAMLRequest' => $this->fixture('authn_request')]);
        $this->makeSpWrapper()->handleAuthnRequest($request, validate: true);
    }

    #[Test]
    public function handle_authn_request_throws_on_invalid_signature(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('Invalid signature');

        $request = $this->makeGetRequest('/sso', ['SAMLRequest' => $this->fixture('authn_request')]);
        $this->makeSpWrapper()->handleAuthnRequest($request, validate: true, issuer: $this->makeSp());
    }

    #[Test]
    public function handle_authn_request_validates_signature_when_requested(): void
    {
        $spWithSigning = $this->makeSpWrapper($this->makeSpWithSigning());

        $response = $spWithSigning->sendAuthnRequest($this->makeIdp());
        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $params);
        $request = $this->makeGetRequest('/sso', $params);

        $message = $this->makeSpWrapper()->handleAuthnRequest($request, validate: true, issuer: $this->makeSpWithSigning());

        $this->assertInstanceOf(AuthnRequest::class, $message);
    }

    #[Test]
    public function handle_logout_request_throws_when_validate_requires_issuer(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('An issuer must be provided to validate the signature');

        $request = $this->makeGetRequest('/slo', ['SAMLRequest' => $this->fixture('logout_request')]);
        $this->makeSpWrapper()->handleLogoutRequest($request, validate: true);
    }

    #[Test]
    public function handle_logout_request_throws_on_invalid_signature(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('Invalid signature');

        $request = $this->makeGetRequest('/slo', ['SAMLRequest' => $this->fixture('logout_request')]);
        $this->makeSpWrapper()->handleLogoutRequest($request, validate: true, issuer: $this->makeIdp());
    }

    #[Test]
    public function handle_logout_request_validates_signature_when_requested(): void
    {
        $idpWithSigning = $this->makeIdpWrapper($this->makeIdpWithSigning());

        $response = $idpWithSigning->sendLogoutRequest($this->makeSp(), 'user@example.com');
        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $params);
        $request = $this->makeGetRequest('/slo', $params);

        $message = $this->makeSpWrapper()->handleLogoutRequest($request, validate: true, issuer: $this->makeIdpWithSigning());

        $this->assertInstanceOf(LogoutRequest::class, $message);
    }

    #[Test]
    public function handle_logout_response_throws_when_validate_requires_issuer(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('An issuer must be provided to validate the signature');

        $request = $this->makeGetRequest('/slo', ['SAMLResponse' => $this->fixture('logout_response')]);
        $this->makeSpWrapper()->handleLogoutResponse($request, validate: true);
    }

    #[Test]
    public function handle_logout_response_throws_on_invalid_signature(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('Invalid signature');

        $request = $this->makeGetRequest('/slo', ['SAMLResponse' => $this->fixture('logout_response')]);
        $this->makeSpWrapper()->handleLogoutResponse($request, validate: true, issuer: $this->makeIdp());
    }

    #[Test]
    public function handle_logout_response_validates_signature_when_requested(): void
    {
        $idpWithSigning = $this->makeIdpWrapper($this->makeIdpWithSigning());

        $response = $idpWithSigning->sendLogoutResponse($this->makeSp());
        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $params);
        $request = $this->makeGetRequest('/slo', $params);

        $message = $this->makeSpWrapper()->handleLogoutResponse($request, validate: true, issuer: $this->makeIdpWithSigning());

        $this->assertInstanceOf(LogoutResponse::class, $message);
    }
}
