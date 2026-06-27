<?php

namespace Litesaml\Models\Messages;

readonly class Attribute
{
    /**
     * @param array<mixed> $values
     */
    public function __construct(
        public string $name,
        public array $values,
        public bool $encrypted = false,
    ) {
    }
}
