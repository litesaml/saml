<?php

namespace Litesaml\Models\Descriptors;

readonly class PublicKey extends Key
{
    /** @return array{start: string, end: string} */
    protected function getHeaders(): array
    {
        return [
            'start' => '-----BEGIN CERTIFICATE-----',
            'end' => '-----END CERTIFICATE-----',
        ];
    }
}
