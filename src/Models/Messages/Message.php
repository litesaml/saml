<?php

namespace Litesaml\Models\Messages;

abstract readonly class Message
{
    public function __construct(
        public string $id,
        public string $issuer,
        public ?Signature $signature,
    ) {}
}
