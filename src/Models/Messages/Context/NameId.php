<?php

namespace Litesaml\Models\Messages\Context;

readonly class NameId implements Context
{
    public function __construct(
        public string $value,
        public ?string $format = null,
    ) {
    }
}
