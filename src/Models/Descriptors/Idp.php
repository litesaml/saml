<?php

namespace Litesaml\Models\Descriptors;

readonly class Idp extends Entity
{
    /**
     * @param string[] $nameIdFormats
     */
    public function __construct(
        string $entityId,
        public Endpoint $sso,
        Endpoint $slo,
        ?Certificate $signing = null,
        array $nameIdFormats = [],
    ) {
        parent::__construct($entityId, $slo, $signing, $nameIdFormats);
    }
}
