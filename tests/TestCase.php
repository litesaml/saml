<?php

namespace Tests;

use Litesaml\Enums\BindingType;
use Litesaml\IdentityProviderWrapper;
use Litesaml\Models\Descriptors\Certificate;
use Litesaml\Models\Descriptors\Endpoint;
use Litesaml\Models\Descriptors\Idp;
use Litesaml\Models\Descriptors\PrivateKey;
use Litesaml\Models\Descriptors\PublicKey;
use Litesaml\Models\Descriptors\Sp;
use Litesaml\ServiceProviderWrapper;
use Litesaml\Support\MessageHandler;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ServerRequestInterface;

abstract class TestCase extends \PHPUnit\Framework\TestCase
{
    protected function fixture(string $name, bool $deflate = true): string
    {
        $xml = file_get_contents(__DIR__ . '/fixtures/' . $name . '.xml');

        return $deflate ? base64_encode(gzdeflate($xml)) : base64_encode($xml);
    }

    protected function makeFactory(): Psr17Factory
    {
        return new Psr17Factory();
    }

    /** @param array<string, string> $params */
    protected function makeGetRequest(string $uri, array $params): ServerRequestInterface
    {
        if (!str_contains($uri, '?') && !empty($params)) {
            $uri .= '?' . http_build_query($params);
        }

        return $this->makeFactory()->createServerRequest('GET', $uri);
    }

    /** @param array<string, string> $params */
    protected function makePostRequest(string $uri, array $params): ServerRequestInterface
    {
        return $this->makeFactory()->createServerRequest('POST', $uri)->withParsedBody($params);
    }

    protected function makeSp(): Sp
    {
        return new Sp(
            entityId: 'https://sp.localhost',
            acs: new Endpoint('https://sp.localhost/acs', BindingType::REDIRECT),
            slo: new Endpoint('https://sp.localhost/slo', BindingType::REDIRECT),
        );
    }

    protected function makeSpWithSigning(): Sp
    {
        return new Sp(
            entityId: 'https://sp.localhost',
            acs: new Endpoint('https://sp.localhost/acs', BindingType::REDIRECT),
            slo: new Endpoint('https://sp.localhost/slo', BindingType::REDIRECT),
            signing: new Certificate(
                publicKey: new PublicKey(file_get_contents(__DIR__ . '/fixtures/signing_cert.pem')),
                privateKey: new PrivateKey(file_get_contents(__DIR__ . '/fixtures/signing_key.pem')),
            ),
        );
    }

    protected function makeIdp(): Idp
    {
        return new Idp(
            entityId: 'https://idp.localhost',
            sso: new Endpoint('https://idp.localhost/sso', BindingType::REDIRECT),
            slo: new Endpoint('https://idp.localhost/slo', BindingType::REDIRECT),
        );
    }

    protected function makeIdpWithSigning(): Idp
    {
        return new Idp(
            entityId: 'https://idp.localhost',
            sso: new Endpoint('https://idp.localhost/sso', BindingType::REDIRECT),
            slo: new Endpoint('https://idp.localhost/slo', BindingType::REDIRECT),
            signing: new Certificate(
                publicKey: new PublicKey(file_get_contents(__DIR__ . '/fixtures/signing_cert.pem')),
                privateKey: new PrivateKey(file_get_contents(__DIR__ . '/fixtures/signing_key.pem')),
            ),
        );
    }

    protected function makeMessageHandler(): MessageHandler
    {
        $f = $this->makeFactory();

        return new MessageHandler($f, $f);
    }

    protected function makeIdpWrapper(?Idp $idp = null): IdentityProviderWrapper
    {
        return new IdentityProviderWrapper($idp ?? $this->makeIdp(), $this->makeMessageHandler());
    }

    protected function makeSpWrapper(?Sp $sp = null): ServiceProviderWrapper
    {
        return new ServiceProviderWrapper($sp ?? $this->makeSp(), $this->makeMessageHandler());
    }
}
