<?php

namespace Tests;

use Litesaml\Models\Descriptors\PublicKey;
use PHPUnit\Framework\Attributes\Test;

class KeyTest extends TestCase
{
    #[Test]
    public function to_pem_wraps_raw_value_without_headers(): void
    {
        $raw = 'MIIDWDCCAkCgAwIBAgIBADANBgkqhkiG9w0BAQUFADBFMQswCQYDVQQGEwJBVTE=';
        $pem = (new PublicKey($raw))->toPem();

        $this->assertStringStartsWith('-----BEGIN CERTIFICATE-----', $pem);
        $this->assertStringEndsWith("-----END CERTIFICATE-----\n", $pem);
    }
}
