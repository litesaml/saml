<?php

namespace Litesaml;

use DateTime;
use LightSaml\Helper;
use LightSaml\Model\Assertion\Issuer;
use LightSaml\Model\Protocol as LightSaml;
use LightSaml\Model\Protocol\AuthnRequest as LightSamlAuthnRequest;
use LightSaml\Model\Protocol\LogoutRequest as LightSamlLogoutRequest;
use LightSaml\Model\Protocol\LogoutResponse as LightSamlLogoutResponse;
use LightSaml\Model\Protocol\Status;
use LightSaml\Model\Protocol\StatusCode;
use LightSaml\SamlConstants;
use Litesaml\Exceptions\SamlException;
use Litesaml\Models\Descriptors\Idp;
use Litesaml\Models\Descriptors\Role;
use Litesaml\Models\Descriptors\Sp;
use Litesaml\Models\Messages\Attribute;
use Litesaml\Models\Messages\AuthnRequest;
use Litesaml\Models\Messages\AuthnResponse;
use Litesaml\Models\Messages\LogoutRequest;
use Litesaml\Models\Messages\LogoutResponse;
use Litesaml\Models\Messages\Message;
use Litesaml\Support\MessageHandler;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

class ServiceProviderWrapper
{
    public function __construct(private Sp $sp) {}

    public function sendAuthnRequest(Idp $recipient): SymfonyResponse
    {
        $authnRequest = (new LightSamlAuthnRequest())
            ->setAssertionConsumerServiceURL($this->sp->acs->location)
            ->setProtocolBinding($this->sp->acs->getBinding())
            ->setID(Helper::generateID())
            ->setIssueInstant(new DateTime())
            ->setDestination($recipient->sso->location)
            ->setIssuer(new Issuer($this->sp->entityId));

        return MessageHandler::send($authnRequest, $this->sp, $recipient->sso);
    }

    public function handleAuthnResponse(SymfonyRequest $request): AuthnResponse
    {
        $message = MessageHandler::unpack($request);

        if (!$message instanceof LightSaml\Response) {
            throw new SamlException('Wrong request received');
        }

        $attributes = [];

        foreach ($message->getAllAssertions() as $assertion) {
            foreach ($assertion->getAllAttributeStatements() as $attributeStatement) {
                foreach ($attributeStatement->getAllAttributes() as $attribute) {
                    $attributes[] = new Attribute(
                        name: $attribute->getName(),
                        value: $attribute->getFirstAttributeValue(),
                    );
                }
            }
        }

        return new AuthnResponse(
            id: $message->getID(),
            issuer: $message->getIssuer()->getValue(),
            signature: MessageHandler::extractSignature($message),
            attributes: $attributes,
        );
    }

    public function handleAuthnRequest(SymfonyRequest $request): AuthnRequest
    {
        $message = MessageHandler::unpack($request);

        if (!$message instanceof LightSaml\AuthnRequest) {
            throw new SamlException('Wrong request received');
        }

        return new AuthnRequest(
            id: $message->getID(),
            issuer: $message->getIssuer()->getValue(),
            signature: MessageHandler::extractSignature($message),
        );
    }

    public function sendLogoutRequest(Role $recipient): SymfonyResponse
    {
        $logoutRequest = (new LightSamlLogoutRequest())
            ->setID(Helper::generateID())
            ->setIssueInstant(new DateTime())
            ->setDestination($recipient->slo->location)
            ->setIssuer(new Issuer($this->sp->entityId));

        return MessageHandler::send($logoutRequest, $this->sp, $recipient->slo);
    }

    public function sendLogoutResponse(Role $recipient): SymfonyResponse
    {
        $logoutResponse = (new LightSamlLogoutResponse())
            ->setStatus(new Status(new StatusCode(SamlConstants::STATUS_SUCCESS)))
            ->setID(Helper::generateID())
            ->setIssueInstant(new DateTime())
            ->setDestination($recipient->slo->location)
            ->setIssuer(new Issuer($this->sp->entityId));

        return MessageHandler::send($logoutResponse, $this->sp, $recipient->slo);
    }

    public function handleLogoutRequest(SymfonyRequest $request): LogoutRequest
    {
        $message = MessageHandler::unpack($request);

        if (!$message instanceof LightSaml\LogoutRequest) {
            throw new SamlException('Wrong request received');
        }

        return new LogoutRequest(
            id: $message->getID(),
            issuer: $message->getIssuer()->getValue(),
            signature: MessageHandler::extractSignature($message),
        );
    }

    public function handleLogoutResponse(SymfonyRequest $request): LogoutResponse
    {
        $message = MessageHandler::unpack($request);

        if (!$message instanceof LightSaml\LogoutResponse) {
            throw new SamlException('Wrong request received');
        }

        return new LogoutResponse(
            id: $message->getID(),
            issuer: $message->getIssuer()->getValue(),
            signature: MessageHandler::extractSignature($message),
        );
    }

    public function validateSignature(Message $message, Role $issuer): bool
    {
        return MessageHandler::validateSignature($message, $issuer);
    }
}
