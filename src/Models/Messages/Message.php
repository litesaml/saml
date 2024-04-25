<?php

namespace Litesaml\Models\Messages;

use Bluestone\DataTransferObject\DataTransferObject;
use RobRichards\XMLSecLibs\XMLSecurityDSig;

abstract class Message extends DataTransferObject
{
    public string $id;

    public string $issuer;

    public ?Signature $signature;
}
