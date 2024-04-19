<?php

namespace Litesaml\Models\Descriptors;

use Bluestone\DataTransferObject\DataTransferObject;
use LightSaml\SamlConstants;
use Litesaml\Enums\BindingType;

class Endpoint extends DataTransferObject
{
    public string $location;

    public BindingType $binding;

    public function getBinding(): string
    {
        return match ($this->binding) {
            BindingType::REDIRECT => SamlConstants::BINDING_SAML2_HTTP_REDIRECT,
            BindingType::POST => SamlConstants::BINDING_SAML2_HTTP_POST,
        };
    }
}
