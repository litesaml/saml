<?php

namespace Litesaml\Models\Descriptors;

abstract readonly class Entity
{
    public function __construct(
        public string $entityId,
        public Endpoint $slo,
        public ?Certificate $signing = null,
    ) {
    }
}
