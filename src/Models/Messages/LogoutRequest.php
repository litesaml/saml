<?php

namespace Litesaml\Models\Messages;

readonly class LogoutRequest extends Message
{
    public function __construct(
        string $id,
        string $issuer,
        public ?string $nameId = null,
        public ?string $sessionIndex = null,
        ?string $relayState = null,
    ) {
        parent::__construct($id, $issuer, $relayState);
    }
}
