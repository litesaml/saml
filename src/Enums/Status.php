<?php

namespace Litesaml\Enums;

use Litesaml\Exceptions\SamlException;

enum Status: string
{
    public static function fromUrn(string $urn): self
    {
        return self::tryFrom($urn) ?? throw new SamlException('Unsupported status: ' . $urn);
    }

    case SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';
    case REQUESTER = 'urn:oasis:names:tc:SAML:2.0:status:Requester';
    case RESPONDER = 'urn:oasis:names:tc:SAML:2.0:status:Responder';
    case VERSION_MISMATCH = 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch';
}
