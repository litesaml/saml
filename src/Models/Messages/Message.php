<?php

namespace Litesaml\Models\Messages;

use Bluestone\DataTransferObject\DataTransferObject;

abstract class Message extends DataTransferObject
{
    public string $id;

    public string $issuer;
}
