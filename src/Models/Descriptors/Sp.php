<?php

namespace Litesaml\Models\Descriptors;

readonly class Sp extends Entity
{
    /**
     * @param string[] $nameIdFormats
     */
    public function __construct(
        string $entityId,
        public Endpoint $acs,
        Endpoint $slo,
        ?Certificate $signing = null,
        public ?Certificate $encryption = null,
        array $nameIdFormats = [],
    ) {
        parent::__construct($entityId, $slo, $signing, $nameIdFormats);
    }
}
