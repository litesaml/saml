<?php

namespace Tests;

use Litesaml\Enums\BindingType;
use Litesaml\Exceptions\SamlException;
use PHPUnit\Framework\Attributes\Test;

class BindingTypeTest extends TestCase
{
    #[Test]
    public function from_urn_throws_on_unsupported_urn(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('Unsupported binding');

        BindingType::fromUrn('urn:oasis:names:tc:SAML:2.0:bindings:SOAP');
    }
}
