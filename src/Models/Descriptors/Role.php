<?php

namespace Litesaml\Models\Descriptors;

use Bluestone\DataTransferObject\DataTransferObject;

abstract class Role extends DataTransferObject
{
    public string $entityId;
}
