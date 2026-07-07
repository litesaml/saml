<?php

namespace Litesaml\Models\Messages;

readonly class AuthnRequest extends Message
{
    public function __construct(
        string $id,
        string $issuer,
        ?string $relayState = null,
        public ?string $nameIdPolicyFormat = null,
    ) {
        parent::__construct($id, $issuer, $relayState);
    }
}
