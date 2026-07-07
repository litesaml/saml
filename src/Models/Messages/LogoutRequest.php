<?php

namespace Litesaml\Models\Messages;

use Litesaml\Models\Messages\Context\NameId;

readonly class LogoutRequest extends Message
{
    public function __construct(
        string $id,
        string $issuer,
        public ?NameId $nameId = null,
        public ?string $sessionIndex = null,
        ?string $relayState = null,
    ) {
        parent::__construct($id, $issuer, $relayState);
    }
}
