<?php

namespace Litesaml\Models\Descriptors;

readonly class Certificate
{
    public function __construct(
        public PublicKey $publicKey,
        public ?PrivateKey $privateKey = null,
    ) {
    }
}
