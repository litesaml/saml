<?php

namespace Tests;

use Litesaml\Models\Messages\AuthnRequest;
use Litesaml\Saml;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

class SamlTest extends TestCase
{
    #[Test]
    public function can_handle_authn_request(): void
    {
        $authnRequest = MessageFactory::authnRequest();

        $symfonyRequest = SymfonyRequest::create(
            uri: '/sso',
            parameters: ['SAMLRequest' => $authnRequest]
        );

        $saml = new Saml();

        $message = $saml->handleAuthnRequest($symfonyRequest);

        $this->assertInstanceOf(AuthnRequest::class, $message);

        $this->assertEquals('MESSAGE-ID', $message->id);
        $this->assertEquals('https://sp.localhost', $message->issuer);
    }
}
