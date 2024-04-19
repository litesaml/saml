<?php

namespace Tests;

use DateTime;
use LightSaml\Context\Profile\MessageContext;
use LightSaml\Model\Assertion\Issuer;
use LightSaml\Model\Protocol\AuthnRequest;
use LightSaml\Model\Protocol\SamlMessage;
use LightSaml\SamlConstants;

class MessageFactory
{
    public static function authnRequest(): string
    {
        $authnRequest = new AuthnRequest();

        $authnRequest
            ->setAssertionConsumerServiceURL('https://sp.localhost/acs')
            ->setProtocolBinding(SamlConstants::BINDING_SAML2_HTTP_REDIRECT)
            ->setID('MESSAGE-ID')
            ->setIssueInstant(new DateTime())
            ->setDestination('https://idp.localhost/sso')
            ->setIssuer(new Issuer('https://sp.localhost'));

        return self::encode($authnRequest);
    }

    private static function encode(SamlMessage $message): string
    {
        $messageContext = new MessageContext();
        $messageContext->setMessage($message);

        $serializationContext = $messageContext->getSerializationContext();
        $message->serialize($serializationContext->getDocument(), $serializationContext);
        $xml = $serializationContext->getDocument()->saveXML();

        $xml = gzdeflate($xml);

        return base64_encode($xml);
    }
}
