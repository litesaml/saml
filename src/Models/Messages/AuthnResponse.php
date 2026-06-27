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
        ?Signature $signature,
        public array $attributes,
        public ?Status $status = null,
        public ?string $nameId = null,
        public ?string $inResponseTo = null,
    ) {
        parent::__construct($id, $issuer, $signature);
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
