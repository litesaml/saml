<?php

namespace Litesaml\Models\Descriptors;

readonly class PrivateKey extends Key
{
    public function __construct(
        string $value,
        public string $passphrase = '',
    ) {
        parent::__construct($value);
    }

    /** @return array{start: string, end: string} */
    protected function getHeaders(): array
    {
        return [
            'start' => '-----BEGIN PRIVATE KEY-----',
            'end' => '-----END PRIVATE KEY-----',
        ];
    }
}
