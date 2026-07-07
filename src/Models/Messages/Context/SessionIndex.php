<?php

namespace Litesaml\Models\Messages\Context;

readonly class SessionIndex implements Context
{
    public function __construct(
        public string $value,
    ) {
    }
}
