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
            new Attribute(name: 'email', values: ['user@example.com']),
            new Attribute(name: 'roles', values: ['admin', 'editor']),
        ];

        $response = $this->makeIdpWrapper()->sendAuthnResponse($this->makeSp(), $attributes);

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
        $this->assertEquals('user@example.com', $message->nameId);
        $this->assertEquals('SESSION-INDEX-ID', $message->sessionIndex);
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

    #[Test]
    public function handle_authn_request_throws_when_validate_requires_issuer(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('An issuer must be provided to validate the signature');

        $request = $this->makeGetRequest('/sso', ['SAMLRequest' => $this->fixture('authn_request')]);
        $this->makeIdpWrapper()->handleAuthnRequest($request, validate: true);
    }

    #[Test]
    public function handle_authn_request_throws_on_invalid_signature(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('Invalid signature');

        $request = $this->makeGetRequest('/sso', ['SAMLRequest' => $this->fixture('authn_request')]);
        $this->makeIdpWrapper()->handleAuthnRequest($request, validate: true, issuer: $this->makeSp());
    }

    #[Test]
    public function handle_authn_request_validates_signature_when_requested(): void
    {
        $spWithSigning = $this->makeSpWrapper($this->makeSpWithSigning());

        $response = $spWithSigning->sendAuthnRequest($this->makeIdp());
        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $params);
        $request = $this->makeGetRequest('/sso', $params);

        $message = $this->makeIdpWrapper()->handleAuthnRequest($request, validate: true, issuer: $this->makeSpWithSigning());

        $this->assertInstanceOf(AuthnRequest::class, $message);
    }

    #[Test]
    public function handle_logout_request_throws_when_validate_requires_issuer(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('An issuer must be provided to validate the signature');

        $request = $this->makeGetRequest('/slo', ['SAMLRequest' => $this->fixture('logout_request')]);
        $this->makeIdpWrapper()->handleLogoutRequest($request, validate: true);
    }

    #[Test]
    public function handle_logout_request_throws_on_invalid_signature(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('Invalid signature');

        $request = $this->makeGetRequest('/slo', ['SAMLRequest' => $this->fixture('logout_request')]);
        $this->makeIdpWrapper()->handleLogoutRequest($request, validate: true, issuer: $this->makeSp());
    }

    #[Test]
    public function handle_logout_request_validates_signature_when_requested(): void
    {
        $spWithSigning = $this->makeSpWrapper($this->makeSpWithSigning());

        $response = $spWithSigning->sendLogoutRequest($this->makeIdp(), 'user@example.com');
        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $params);
        $request = $this->makeGetRequest('/slo', $params);

        $message = $this->makeIdpWrapper()->handleLogoutRequest($request, validate: true, issuer: $this->makeSpWithSigning());

        $this->assertInstanceOf(LogoutRequest::class, $message);
    }

    #[Test]
    public function handle_logout_response_throws_when_validate_requires_issuer(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('An issuer must be provided to validate the signature');

        $request = $this->makeGetRequest('/slo', ['SAMLResponse' => $this->fixture('logout_response')]);
        $this->makeIdpWrapper()->handleLogoutResponse($request, validate: true);
    }

    #[Test]
    public function handle_logout_response_throws_on_invalid_signature(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('Invalid signature');

        $request = $this->makeGetRequest('/slo', ['SAMLResponse' => $this->fixture('logout_response')]);
        $this->makeIdpWrapper()->handleLogoutResponse($request, validate: true, issuer: $this->makeSp());
    }

    #[Test]
    public function handle_logout_response_validates_signature_when_requested(): void
    {
        $spWithSigning = $this->makeSpWrapper($this->makeSpWithSigning());

        $response = $spWithSigning->sendLogoutResponse($this->makeIdp());
        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $params);
        $request = $this->makeGetRequest('/slo', $params);

        $message = $this->makeIdpWrapper()->handleLogoutResponse($request, validate: true, issuer: $this->makeSpWithSigning());

        $this->assertInstanceOf(LogoutResponse::class, $message);
    }
}
