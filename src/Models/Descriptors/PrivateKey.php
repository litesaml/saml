<?php

namespace Litesaml\Models\Descriptors;

class PrivateKey extends Key
{
    public string $passphrase = '';

    protected function getHeaders(): array
    {
        return [
            'start' => '-----BEGIN PRIVATE KEY-----',
            'end' => '-----END PRIVATE KEY-----',
        ];
    }
}
