<?php

namespace Litesaml\Models\Descriptors;

class PublicKey extends Key
{
    protected function getHeaders(): array
    {
        return [
            'start' => '-----BEGIN CERTIFICATE-----',
            'end' => '-----END CERTIFICATE-----',
        ];
    }
}
