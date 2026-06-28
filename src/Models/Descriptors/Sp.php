<?php

namespace Litesaml\Models\Descriptors;

readonly class Sp extends Entity
{
    public function __construct(
        string $entityId,
        public Endpoint $acs,
        Endpoint $slo,
        ?Certificate $signing = null,
        public ?Certificate $encryption = null,
    ) {
        parent::__construct($entityId, $slo, $signing);
    }
}
