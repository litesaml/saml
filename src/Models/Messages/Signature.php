<?php

namespace Litesaml\Models\Messages;

use Bluestone\DataTransferObject\DataTransferObject;

class Signature extends DataTransferObject
{
    public string $value;
    public string $algorithm;
    public string $data;
}
