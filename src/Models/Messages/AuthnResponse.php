<?php

namespace Litesaml\Models\Messages;

use Litesaml\Enums\Status;

readonly class AuthnResponse extends Message
{
    /**
     * @param Attribute[] $attributes
     */
    public function __construct(
        string $id,
        string $issuer,
        public array $attributes,
        public ?Status $status = null,
        public ?NameId $nameId = null,
        public ?string $inResponseTo = null,
        public ?string $sessionIndex = null,
        ?string $relayState = null,
    ) {
        parent::__construct($id, $issuer, $relayState);
    }

    public function isSuccess(): bool
    {
        return $this->status === Status::SUCCESS;
    }

    public function getAttributeByName(string $name): ?Attribute
    {
        foreach ($this->attributes as $attribute) {
            if ($attribute->name === $name) {
                return $attribute;
            }
        }

        return null;
    }
}
