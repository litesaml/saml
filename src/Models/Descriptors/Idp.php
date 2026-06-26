<?php

namespace Litesaml\Models\Descriptors;

readonly class Idp extends Role
{
    public function __construct(
        string $entityId,
        public Endpoint $sso,
        public Endpoint $slo,
        ?Certificate $signing = null,
    ) {
        parent::__construct($entityId, $signing);
    }
}
