<?php

namespace Litesaml\Models\Messages;

readonly class Signature
{
    public function __construct(
        public string $value,
        public string $algorithm,
        public string $data,
    ) {
    }
}
