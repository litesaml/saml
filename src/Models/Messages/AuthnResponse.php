<?php

namespace Litesaml\Models\Messages;

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
    ) {
        parent::__construct($id, $issuer, $signature);
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
