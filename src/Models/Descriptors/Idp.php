<?php

namespace Litesaml\Models\Descriptors;

readonly class Idp extends Entity
{
    public function __construct(
        string $entityId,
        public Endpoint $sso,
        Endpoint $slo,
        ?Certificate $signing = null,
    ) {
        parent::__construct($entityId, $slo, $signing);
    }
}
