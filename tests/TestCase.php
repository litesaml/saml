<?php

namespace Tests;

use Litesaml\Enums\BindingType;
use Litesaml\Models\Descriptors\Certificate;
use Litesaml\Models\Descriptors\Endpoint;
use Litesaml\Models\Descriptors\Idp;
use Litesaml\Models\Descriptors\PrivateKey;
use Litesaml\Models\Descriptors\PublicKey;
use Litesaml\Models\Descriptors\Sp;

abstract class TestCase extends \PHPUnit\Framework\TestCase
{
    protected function fixture(string $name, bool $deflate = true): string
    {
        $xml = file_get_contents(__DIR__ . '/fixtures/' . $name . '.xml');

        return $deflate ? base64_encode(gzdeflate($xml)) : base64_encode($xml);
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
}
