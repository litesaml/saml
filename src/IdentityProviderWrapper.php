<?php

namespace Litesaml;

use DateTime;
use LightSaml\Helper;
use LightSaml\Model\Assertion\Assertion;
use LightSaml\Model\Assertion\Attribute as LightSamlAttribute;
use LightSaml\Model\Assertion\AttributeStatement;
use LightSaml\Model\Assertion\Issuer;
use LightSaml\Model\Protocol as LightSaml;
use LightSaml\Model\Protocol\AuthnRequest as LightSamlAuthnRequest;
use LightSaml\Model\Protocol\LogoutRequest as LightSamlLogoutRequest;
use LightSaml\Model\Protocol\LogoutResponse as LightSamlLogoutResponse;
use LightSaml\Model\Protocol\Response as LightSamlAuthnResponse;
use LightSaml\Model\Protocol\Status;
use LightSaml\Model\Protocol\StatusCode;
use LightSaml\SamlConstants;
use Litesaml\Exceptions\SamlException;
use Litesaml\Models\Descriptors\Idp;
use Litesaml\Models\Descriptors\Role;
use Litesaml\Models\Descriptors\Sp;
use Litesaml\Models\Messages\Attribute;
use Litesaml\Models\Messages\AuthnRequest;
use Litesaml\Models\Messages\LogoutRequest;
use Litesaml\Models\Messages\LogoutResponse;
use Litesaml\Models\Messages\Message;
use Litesaml\Support\MessageHandler;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;

class IdentityProviderWrapper
{
    public function __construct(
        private Idp $idp,
        private ResponseFactoryInterface $responseFactory,
        private StreamFactoryInterface $streamFactory,
    ) {}

    /**
     * @param Attribute[] $attributes
     */
    public function sendAuthnResponse(Sp $recipient, array $attributes): ResponseInterface
    {
        $response = new LightSamlAuthnResponse();

        $response
            ->setStatus(new Status(new StatusCode(SamlConstants::STATUS_SUCCESS)))
            ->setID(Helper::generateID())
            ->setIssueInstant(new DateTime())
            ->setDestination($recipient->acs->location)
            ->setIssuer(new Issuer($this->idp->entityId));

        foreach ($attributes as $attribute) {
            $assertion = (new Assertion())
                ->setId(Helper::generateID())
                ->setIssueInstant(new DateTime())
                ->setIssuer($response->getIssuer())
                ->addItem(
                    (new AttributeStatement())
                        ->addAttribute(new LightSamlAttribute($attribute->name, $attribute->value))
                );

            $response->addAssertion($assertion);
        }

        return MessageHandler::send($response, $this->idp, $recipient->acs, $this->responseFactory, $this->streamFactory);
    }

    public function handleAuthnRequest(ServerRequestInterface $request): AuthnRequest
    {
        $message = MessageHandler::unpack($request);

        if (!$message instanceof LightSamlAuthnRequest) {
            throw new SamlException('Wrong request received');
        }

        return new AuthnRequest(
            id: $message->getID(),
            issuer: $message->getIssuer()->getValue(),
            signature: MessageHandler::extractSignature($message),
        );
    }

    public function sendLogoutRequest(Role $recipient): ResponseInterface
    {
        $logoutRequest = (new LightSamlLogoutRequest())
            ->setID(Helper::generateID())
            ->setIssueInstant(new DateTime())
            ->setDestination($recipient->slo->location)
            ->setIssuer(new Issuer($this->idp->entityId));

        return MessageHandler::send($logoutRequest, $this->idp, $recipient->slo, $this->responseFactory, $this->streamFactory);
    }

    public function sendLogoutResponse(Role $recipient): ResponseInterface
    {
        $logoutResponse = (new LightSamlLogoutResponse())
            ->setStatus(new Status(new StatusCode(SamlConstants::STATUS_SUCCESS)))
            ->setID(Helper::generateID())
            ->setIssueInstant(new DateTime())
            ->setDestination($recipient->slo->location)
            ->setIssuer(new Issuer($this->idp->entityId));

        return MessageHandler::send($logoutResponse, $this->idp, $recipient->slo, $this->responseFactory, $this->streamFactory);
    }

    public function handleLogoutRequest(ServerRequestInterface $request): LogoutRequest
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

    public function handleLogoutResponse(ServerRequestInterface $request): LogoutResponse
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
