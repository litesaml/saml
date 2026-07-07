<?php

namespace Litesaml\Models\Messages\Context;

readonly class RelayState implements Context
{
    public function __construct(
        public string $value,
    ) {
    }
}
