<?php

namespace Litesaml\Models\Descriptors;

use Bluestone\DataTransferObject\DataTransferObject;

class Certificate extends DataTransferObject
{
    public PublicKey $publicKey;
    public PrivateKey $privateKey;
}
