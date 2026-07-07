<?php

namespace Litesaml\Models\Messages\Context;

readonly class NameIdPolicyFormat implements Context
{
    public function __construct(
        public string $value,
    ) {
    }
}
