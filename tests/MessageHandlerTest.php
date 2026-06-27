<?php

namespace Tests;

use Litesaml\Models\Messages\AuthnRequest;
use Litesaml\Models\Messages\Signature;
use PHPUnit\Framework\Attributes\Test;

class MessageHandlerTest extends TestCase
{
    #[Test]
    public function validate_signature_returns_false_on_unsupported_algorithm(): void
    {
        $message = new AuthnRequest(
            id: 'id',
            issuer: 'https://sp.localhost',
            signature: new Signature(
                value: 'garbage',
                algorithm: 'urn:invalid:algorithm',
                data: 'data',
            ),
        );

        $this->assertFalse(
            $this->makeMessageHandler()->validateSignature($message, $this->makeSpWithSigning())
        );
    }
}
