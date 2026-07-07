<?php

namespace Litesaml\Models\Messages\Context;

readonly class Attribute implements Context
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
