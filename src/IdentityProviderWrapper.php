<?php

namespace Litesaml;

use DateTime;
use LightSaml\Context\Model\SerializationContext;
use LightSaml\Credential\X509Certificate;
use LightSaml\Helper;
use LightSaml\Model\Assertion\Assertion;
use LightSaml\Model\Assertion\Attribute as LightSamlAttribute;
use LightSaml\Model\Assertion\AttributeStatement;
use LightSaml\Model\Assertion\Issuer;
use LightSaml\Model\Assertion\NameID;
use LightSaml\Model\Metadata\EntityDescriptor;
use LightSaml\Model\Metadata\IdpSsoDescriptor;
use LightSaml\Model\Metadata\KeyDescriptor;
use LightSaml\Model\Metadata\SingleLogoutService;
use LightSaml\Model\Metadata\SingleSignOnService;
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
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class IdentityProviderWrapper
{
    public function __construct(
        private Idp $idp,
        private MessageHandler $messageHandler,
    ) {
    }

    public function generateMetadata(): string
    {
        $idpSsoDescriptor = new IdpSsoDescriptor();

        if ($this->idp->signing) {
            $cert = (new X509Certificate())->loadPem($this->idp->signing->publicKey->toPem());
            $idpSsoDescriptor->addKeyDescriptor(new KeyDescriptor(KeyDescriptor::USE_SIGNING, $cert));
        }

        $idpSsoDescriptor->addSingleSignOnService(
            (new SingleSignOnService())
                ->setBinding($this->idp->sso->getBinding())
                ->setLocation($this->idp->sso->location)
        );

        $idpSsoDescriptor->addSingleLogoutService(
            (new SingleLogoutService())
                ->setBinding($this->idp->slo->getBinding())
                ->setLocation($this->idp->slo->location)
        );

        $entityDescriptor = (new EntityDescriptor($this->idp->entityId))
            ->addItem($idpSsoDescriptor);

        $context = new SerializationContext();
        $entityDescriptor->serialize($context->getDocument(), $context);

        return (string) $context->getDocument()->saveXML();
    }

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
            $lightSamlAttribute = new LightSamlAttribute($attribute->name);
            foreach ($attribute->values as $value) {
                $lightSamlAttribute->addAttributeValue($value);
            }

            $assertion = (new Assertion())
                ->setId(Helper::generateID())
                ->setIssueInstant(new DateTime())
                ->setIssuer($response->getIssuer())
                ->addItem((new AttributeStatement())->addAttribute($lightSamlAttribute));

            $response->addAssertion($assertion);
        }

        return $this->messageHandler->send($response, $this->idp, $recipient->acs);
    }

    public function handleAuthnRequest(ServerRequestInterface $request): AuthnRequest
    {
        $message = $this->messageHandler->unpack($request);

        if (!$message instanceof LightSamlAuthnRequest) {
            throw new SamlException('Wrong request received');
        }

        return new AuthnRequest(
            id: $message->getID(),
            issuer: $message->getIssuer()->getValue(),
            signature: $this->messageHandler->extractSignature($message),
            relayState: $message->getRelayState(),
        );
    }

    public function sendLogoutRequest(Role $recipient, string $nameId, ?string $relayState = null, ?string $sessionIndex = null): ResponseInterface
    {
        $logoutRequest = (new LightSamlLogoutRequest())
            ->setID(Helper::generateID())
            ->setIssueInstant(new DateTime())
            ->setDestination($recipient->slo->location)
            ->setIssuer(new Issuer($this->idp->entityId))
            ->setNameID(new NameID($nameId))
            ->setSessionIndex($sessionIndex)
            ->setRelayState($relayState);

        return $this->messageHandler->send($logoutRequest, $this->idp, $recipient->slo);
    }

    public function sendLogoutResponse(Role $recipient): ResponseInterface
    {
        $logoutResponse = (new LightSamlLogoutResponse())
            ->setStatus(new Status(new StatusCode(SamlConstants::STATUS_SUCCESS)))
            ->setID(Helper::generateID())
            ->setIssueInstant(new DateTime())
            ->setDestination($recipient->slo->location)
            ->setIssuer(new Issuer($this->idp->entityId));

        return $this->messageHandler->send($logoutResponse, $this->idp, $recipient->slo);
    }

    public function handleLogoutRequest(ServerRequestInterface $request): LogoutRequest
    {
        $message = $this->messageHandler->unpack($request);

        if (!$message instanceof LightSamlLogoutRequest) {
            throw new SamlException('Wrong request received');
        }

        return new LogoutRequest(
            id: $message->getID(),
            issuer: $message->getIssuer()->getValue(),
            signature: $this->messageHandler->extractSignature($message),
            nameId: $message->getNameID()->getValue(),
            sessionIndex: $message->getSessionIndex(),
            relayState: $message->getRelayState(),
        );
    }

    public function handleLogoutResponse(ServerRequestInterface $request): LogoutResponse
    {
        $message = $this->messageHandler->unpack($request);

        if (!$message instanceof LightSamlLogoutResponse) {
            throw new SamlException('Wrong request received');
        }

        return new LogoutResponse(
            id: $message->getID(),
            issuer: $message->getIssuer()->getValue(),
            signature: $this->messageHandler->extractSignature($message),
            relayState: $message->getRelayState(),
        );
    }

    public function validateSignature(Message $message, Role $issuer): bool
    {
        return $this->messageHandler->validateSignature($message, $issuer);
    }
}
