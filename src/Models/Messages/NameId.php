<?php

namespace Litesaml\Models\Messages;

readonly class NameId
{
    public function __construct(
        public string $value,
        public ?string $format = null,
    ) {
    }
}
