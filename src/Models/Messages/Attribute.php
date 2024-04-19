<?php

namespace Litesaml\Models\Messages;

use Bluestone\DataTransferObject\DataTransferObject;

class Attribute extends DataTransferObject
{
    public string $name;

    public mixed $value;
}
