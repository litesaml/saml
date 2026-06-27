<?php

namespace Litesaml\Enums;

use LightSaml\SamlConstants;
use Litesaml\Exceptions\SamlException;

enum BindingType
{
    public static function fromUrn(string $urn): self
    {
        return match ($urn) {
            SamlConstants::BINDING_SAML2_HTTP_REDIRECT => self::REDIRECT,
            SamlConstants::BINDING_SAML2_HTTP_POST => self::POST,
            default => throw new SamlException('Unsupported binding: ' . $urn),
        };
    }
    case REDIRECT;
    case POST;
}
