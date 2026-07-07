<?php

namespace Tests;

use Litesaml\Exceptions\SamlException;
use Litesaml\Models\Messages\AuthnRequest;
use Litesaml\Models\Messages\AuthnResponse;
use Litesaml\Models\Messages\Context\Attribute;
use Litesaml\Models\Messages\Context\ContextList;
use Litesaml\Models\Messages\Context\NameId;
use Litesaml\Models\Messages\Context\Validate;
use Litesaml\Models\Messages\LogoutRequest;
use Litesaml\Models\Messages\LogoutResponse;
use Litesaml\Support\MetadataParser;
use PHPUnit\Framework\Attributes\Test;

class IdentityProviderWrapperTest extends TestCase
{
    #[Test]
    public function can_generate_metadata(): void
    {
        $xml = $this->makeIdpWrapper()->generateMetadata();

        $this->assertStringContainsString('EntityDescriptor', $xml);
        $this->assertStringContainsString('https://idp.localhost', $xml);
        $this->assertStringContainsString('IDPSSODescriptor', $xml);
        $this->assertStringContainsString('SingleSignOnService', $xml);
        $this->assertStringContainsString('SingleLogoutService', $xml);
    }

    #[Test]
    public function generate_metadata_includes_key_descriptor_when_signing_configured(): void
    {
        $xml = $this->makeIdpWrapper($this->makeIdpWithSigning())->generateMetadata();

        $this->assertStringContainsString('KeyDescriptor', $xml);
        $this->assertStringContainsString('use="signing"', $xml);
    }

    #[Test]
    public function generate_metadata_includes_name_id_formats_when_configured(): void
    {
        $idp = $this->makeIdpWithNameIdFormats(['urn:oasis:names:tc:SAML:2.0:nameid-format:persistent']);
        $xml = $this->makeIdpWrapper($idp)->generateMetadata();

        $parsed = MetadataParser::parse($xml);

        $this->assertEquals(['urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'], $parsed->nameIdFormats);
    }

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
        $context = new ContextList(
            new Attribute(name: 'email', values: ['user@example.com']),
            new Attribute(name: 'roles', values: ['admin', 'editor']),
        );

        $response = $this->makeIdpWrapper()->sendAuthnResponse($this->makeSp(), $context);

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertStringContainsString('https://sp.localhost/acs', $response->getHeaderLine('Location'));

        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $params);
        $authnResponse = $this->makeSpWrapper()->handleAuthnResponse(
            $this->makeGetRequest('/acs', $params)
        );

        $this->assertEquals(['user@example.com'], $authnResponse->getAttributeByName('email')?->values);
        $this->assertEquals(['admin', 'editor'], $authnResponse->getAttributeByName('roles')?->values);
    }

    #[Test]
    public function can_send_authn_response_with_name_id(): void
    {
        $context = new ContextList(
            new Attribute(name: 'email', values: ['user@example.com']),
            new NameId('user@example.com', 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'),
        );

        $response = $this->makeIdpWrapper()->sendAuthnResponse($this->makeSp(), $context);

        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $params);
        $authnResponse = $this->makeSpWrapper()->handleAuthnResponse(
            $this->makeGetRequest('/acs', $params)
        );

        $this->assertEquals('user@example.com', $authnResponse->nameId?->value);
        $this->assertEquals('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', $authnResponse->nameId?->format);
    }

    #[Test]
    public function can_send_logout_request(): void
    {
        $response = $this->makeIdpWrapper()->sendLogoutRequest(
            $this->makeSp(),
            new ContextList(new NameId('user@example.com')),
        );

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertStringContainsString('https://sp.localhost/slo', $response->getHeaderLine('Location'));
    }

    #[Test]
    public function send_logout_request_throws_when_name_id_missing(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('A NameId is required to send a LogoutRequest');

        $this->makeIdpWrapper()->sendLogoutRequest($this->makeSp());
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
        $this->assertEquals('user@example.com', $message->nameId?->value);
        $this->assertEquals('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', $message->nameId?->format);
        $this->assertEquals('SESSION-INDEX-ID', $message->sessionIndex);
    }

    #[Test]
    public function can_send_logout_request_with_name_id_format(): void
    {
        $response = $this->makeIdpWrapper()->sendLogoutRequest(
            $this->makeSp(),
            new ContextList(new NameId('user@example.com', 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent')),
        );
        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $params);

        $message = $this->makeSpWrapper()->handleLogoutRequest($this->makeGetRequest('/slo', $params));

        $this->assertEquals('user@example.com', $message->nameId?->value);
        $this->assertEquals('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', $message->nameId?->format);
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
    public function send_authn_response_with_encrypted_attribute(): void
    {
        $context = new ContextList(
            new Attribute(name: 'email', values: ['user@example.com']),
            new Attribute(name: 'roles', values: ['admin'], encrypted: true),
        );

        $sp = $this->makeSpWithEncryption();
        $response = $this->makeIdpWrapper()->sendAuthnResponse($sp, $context);

        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $params);
        $authnResponse = $this->makeSpWrapper($sp)->handleAuthnResponse(
            $this->makeGetRequest('/acs', $params)
        );

        $this->assertInstanceOf(AuthnResponse::class, $authnResponse);
        $this->assertEquals(['user@example.com'], $authnResponse->getAttributeByName('email')?->values);
        $this->assertFalse($authnResponse->getAttributeByName('email')?->encrypted);
        $this->assertEquals(['admin'], $authnResponse->getAttributeByName('roles')?->values);
        $this->assertTrue($authnResponse->getAttributeByName('roles')?->encrypted);
    }

    #[Test]
    public function send_authn_response_throws_when_encrypted_attribute_but_no_sp_encryption_cert(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('No encryption certificate configured on recipient SP');

        $context = new ContextList(new Attribute(name: 'roles', values: ['admin'], encrypted: true));

        $this->makeIdpWrapper()->sendAuthnResponse($this->makeSp(), $context);
    }

    #[Test]
    public function handle_authn_request_throws_on_invalid_signature(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('Invalid signature');

        $request = $this->makeGetRequest('/sso', ['SAMLRequest' => $this->fixture('authn_request')]);
        $this->makeIdpWrapper()->handleAuthnRequest($request, new ContextList(new Validate($this->makeSp())));
    }

    #[Test]
    public function handle_authn_request_validates_signature_when_requested(): void
    {
        $spWithSigning = $this->makeSpWrapper($this->makeSpWithSigning());

        $response = $spWithSigning->sendAuthnRequest($this->makeIdp());
        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $params);
        $request = $this->makeGetRequest('/sso', $params);

        $message = $this->makeIdpWrapper()->handleAuthnRequest($request, new ContextList(new Validate($this->makeSpWithSigning())));

        $this->assertInstanceOf(AuthnRequest::class, $message);
    }

    #[Test]
    public function handle_logout_request_throws_on_invalid_signature(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('Invalid signature');

        $request = $this->makeGetRequest('/slo', ['SAMLRequest' => $this->fixture('logout_request')]);
        $this->makeIdpWrapper()->handleLogoutRequest($request, new ContextList(new Validate($this->makeSp())));
    }

    #[Test]
    public function handle_logout_request_validates_signature_when_requested(): void
    {
        $spWithSigning = $this->makeSpWrapper($this->makeSpWithSigning());

        $response = $spWithSigning->sendLogoutRequest($this->makeIdp(), new ContextList(new NameId('user@example.com')));
        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $params);
        $request = $this->makeGetRequest('/slo', $params);

        $message = $this->makeIdpWrapper()->handleLogoutRequest($request, new ContextList(new Validate($this->makeSpWithSigning())));

        $this->assertInstanceOf(LogoutRequest::class, $message);
    }

    #[Test]
    public function handle_logout_response_throws_on_invalid_signature(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('Invalid signature');

        $request = $this->makeGetRequest('/slo', ['SAMLResponse' => $this->fixture('logout_response')]);
        $this->makeIdpWrapper()->handleLogoutResponse($request, new ContextList(new Validate($this->makeSp())));
    }

    #[Test]
    public function handle_logout_request_throws_on_wrong_message_type(): void
    {
        $this->expectException(SamlException::class);

        $request = $this->makeGetRequest('/slo', ['SAMLRequest' => $this->fixture('authn_request')]);
        $this->makeIdpWrapper()->handleLogoutRequest($request);
    }

    #[Test]
    public function handle_logout_response_throws_on_wrong_message_type(): void
    {
        $this->expectException(SamlException::class);

        $request = $this->makeGetRequest('/slo', ['SAMLRequest' => $this->fixture('authn_request')]);
        $this->makeIdpWrapper()->handleLogoutResponse($request);
    }

    #[Test]
    public function handle_logout_response_validates_signature_when_requested(): void
    {
        $spWithSigning = $this->makeSpWrapper($this->makeSpWithSigning());

        $response = $spWithSigning->sendLogoutResponse($this->makeIdp());
        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $params);
        $request = $this->makeGetRequest('/slo', $params);

        $message = $this->makeIdpWrapper()->handleLogoutResponse($request, new ContextList(new Validate($this->makeSpWithSigning())));

        $this->assertInstanceOf(LogoutResponse::class, $message);
    }
}
