<?php

namespace Litesaml\Models\Messages;

use Bluestone\DataTransferObject\Attributes\CastWith;
use Bluestone\DataTransferObject\Casters\ArrayCaster;

class AuthnResponse extends Message
{
    #[CastWith(ArrayCaster::class, type: Attribute::class)]
    public array $attributes;

    public function getAttributeByName(string $name): ?Attribute
    {
        $attributes = array_filter(
            $this->attributes,
            function (Attribute $attr) use ($name) {
                return $attr->name === $name;
            }
        );

        return array_shift($attributes);
    }
}
