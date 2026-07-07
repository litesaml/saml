<?php

namespace Litesaml\Models\Messages\Context;

use Litesaml\Models\Descriptors\Entity;

readonly class Validate implements Context
{
    public function __construct(
        public Entity $issuer,
    ) {
    }
}
