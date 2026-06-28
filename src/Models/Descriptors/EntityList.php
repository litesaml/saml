<?php

namespace Litesaml\Models\Descriptors;

readonly class EntityList
{
    /** @param Entity[] $entities */
    public function __construct(
        public array $entities,
    ) {
    }
}
