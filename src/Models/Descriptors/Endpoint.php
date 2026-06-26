<?php

namespace Litesaml\Models\Descriptors;

use LightSaml\SamlConstants;
use Litesaml\Enums\BindingType;

readonly class Endpoint
{
    public function __construct(
        public string $location,
        public BindingType $binding,
    ) {}

    public function getBinding(): string
    {
        return match ($this->binding) {
            BindingType::REDIRECT => SamlConstants::BINDING_SAML2_HTTP_REDIRECT,
            BindingType::POST => SamlConstants::BINDING_SAML2_HTTP_POST,
        };
    }
}
