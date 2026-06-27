<?php

namespace Litesaml\Models\Messages;

readonly class Attribute
{
    public function __construct(
        public string $name,
        public mixed $value,
    ) {
    }
}
