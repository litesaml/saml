<?php

namespace Litesaml\Models\Descriptors;

abstract readonly class Entity
{
    /**
     * @param string[] $nameIdFormats
     */
    public function __construct(
        public string $entityId,
        public Endpoint $slo,
        public ?Certificate $signing = null,
        public array $nameIdFormats = [],
    ) {
    }
}
