<?php

namespace Litesaml;

use DateTime;
use LightSaml\Context\Model\SerializationContext;
use LightSaml\Credential\X509Certificate;
use LightSaml\Helper;
use LightSaml\Model\Assertion\Assertion;
use LightSaml\Model\Assertion\Attribute as LightSamlAttribute;
use LightSaml\Model\Assertion\AttributeStatement;
use LightSaml\Model\Assertion\EncryptedAssertionWriter;
use LightSaml\Model\Assertion\Issuer;
use LightSaml\Model\Assertion\NameID;
use LightSaml\Model\Assertion\Subject;
use LightSaml\Model\Assertion\SubjectConfirmation;
use LightSaml\Model\Metadata\EntityDescriptor;
use LightSaml\Model\Metadata\IdpSsoDescriptor;
use LightSaml\Model\Metadata\KeyDescriptor;
use LightSaml\Model\Metadata\SingleLogoutService;
use LightSaml\Model\Metadata\SingleSignOnService;
use LightSaml\Model\Protocol\AuthnRequest as LightSamlAuthnRequest;
use LightSaml\Model\Protocol\LogoutRequest as LightSamlLogoutRequest;
use LightSaml\Model\Protocol\LogoutResponse as LightSamlLogoutResponse;
use LightSaml\Model\Protocol\Response as LightSamlAuthnResponse;
use LightSaml\Model\Protocol\SamlMessage;
use LightSaml\Model\Protocol\Status;
use LightSaml\Model\Protocol\StatusCode;
use LightSaml\SamlConstants;
use Litesaml\Exceptions\SamlException;
use Litesaml\Models\Descriptors\Entity;
use Litesaml\Models\Descriptors\Idp;
use Litesaml\Models\Descriptors\Sp;
use Litesaml\Models\Messages\Attribute;
use Litesaml\Models\Messages\AuthnRequest;
use Litesaml\Models\Messages\LogoutRequest;
use Litesaml\Models\Messages\LogoutResponse;
use Litesaml\Support\MessageHandler;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use RobRichards\XMLSecLibs\XMLSecurityKey;

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

        $plainAttributes = array_values(array_filter($attributes, fn ($a) => !$a->encrypted));
        $encryptedAttributes = array_values(array_filter($attributes, fn ($a) => $a->encrypted));

        if (!empty($plainAttributes) || empty($encryptedAttributes)) {
            $attributeStatement = new AttributeStatement();
            foreach ($plainAttributes as $attribute) {
                $lightSamlAttribute = new LightSamlAttribute($attribute->name);
                foreach ($attribute->values as $value) {
                    $lightSamlAttribute->addAttributeValue($value);
                }
                $attributeStatement->addAttribute($lightSamlAttribute);
            }

            $subject = (new Subject())
                ->addSubjectConfirmation(
                    (new SubjectConfirmation())->setMethod(SamlConstants::CONFIRMATION_METHOD_BEARER)
                );

            $response->addAssertion(
                (new Assertion())
                    ->setId(Helper::generateID())
                    ->setIssueInstant(new DateTime())
                    ->setIssuer($response->getIssuer())
                    ->setSubject($subject)
                    ->addItem($attributeStatement)
            );
        }

        if (!empty($encryptedAttributes)) {
            if ($recipient->encryption === null) {
                throw new SamlException('No encryption certificate configured on recipient SP');
            }

            $attributeStatement = new AttributeStatement();
            foreach ($encryptedAttributes as $attribute) {
                $lightSamlAttribute = new LightSamlAttribute($attribute->name);
                foreach ($attribute->values as $value) {
                    $lightSamlAttribute->addAttributeValue($value);
                }
                $attributeStatement->addAttribute($lightSamlAttribute);
            }

            $subject = (new Subject())
                ->addSubjectConfirmation(
                    (new SubjectConfirmation())->setMethod(SamlConstants::CONFIRMATION_METHOD_BEARER)
                );

            $assertion = (new Assertion())
                ->setId(Helper::generateID())
                ->setIssueInstant(new DateTime())
                ->setIssuer($response->getIssuer())
                ->setSubject($subject)
                ->addItem($attributeStatement);

            $encKey = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, ['type' => 'public']);
            $encKey->loadKey($recipient->encryption->publicKey->toPem(), false, true);

            $writer = new EncryptedAssertionWriter();
            $writer->encrypt($assertion, $encKey);
            $response->addEncryptedAssertion($writer);
        }

        return $this->messageHandler->send($response, $this->idp, $recipient->acs);
    }

    public function handleAuthnRequest(ServerRequestInterface $request, bool $validate = false, ?Entity $issuer = null): AuthnRequest
    {
        $message = $this->messageHandler->unpack($request);

        if (!$message instanceof LightSamlAuthnRequest) {
            throw new SamlException('Wrong request received');
        }

        $dto = new AuthnRequest(
            id: $message->getID(),
            issuer: $message->getIssuer()->getValue(),
            relayState: $message->getRelayState(),
        );

        $this->validateIfRequested($message, $validate, $issuer);

        return $dto;
    }

    public function sendLogoutRequest(Entity $recipient, string $nameId, ?string $relayState = null, ?string $sessionIndex = null): ResponseInterface
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

    public function sendLogoutResponse(Entity $recipient): ResponseInterface
    {
        $logoutResponse = (new LightSamlLogoutResponse())
            ->setStatus(new Status(new StatusCode(SamlConstants::STATUS_SUCCESS)))
            ->setID(Helper::generateID())
            ->setIssueInstant(new DateTime())
            ->setDestination($recipient->slo->location)
            ->setIssuer(new Issuer($this->idp->entityId));

        return $this->messageHandler->send($logoutResponse, $this->idp, $recipient->slo);
    }

    public function handleLogoutRequest(ServerRequestInterface $request, bool $validate = false, ?Entity $issuer = null): LogoutRequest
    {
        $message = $this->messageHandler->unpack($request);

        if (!$message instanceof LightSamlLogoutRequest) {
            throw new SamlException('Wrong request received');
        }

        $dto = new LogoutRequest(
            id: $message->getID(),
            issuer: $message->getIssuer()->getValue(),
            nameId: $message->getNameID()->getValue(),
            sessionIndex: $message->getSessionIndex(),
            relayState: $message->getRelayState(),
        );

        $this->validateIfRequested($message, $validate, $issuer);

        return $dto;
    }

    public function handleLogoutResponse(ServerRequestInterface $request, bool $validate = false, ?Entity $issuer = null): LogoutResponse
    {
        $message = $this->messageHandler->unpack($request);

        if (!$message instanceof LightSamlLogoutResponse) {
            throw new SamlException('Wrong request received');
        }

        $dto = new LogoutResponse(
            id: $message->getID(),
            issuer: $message->getIssuer()->getValue(),
            relayState: $message->getRelayState(),
        );

        $this->validateIfRequested($message, $validate, $issuer);

        return $dto;
    }

    private function validateIfRequested(SamlMessage $message, bool $validate, ?Entity $issuer): void
    {
        if (!$validate) {
            return;
        }

        if ($issuer === null) {
            throw new SamlException('An issuer must be provided to validate the signature');
        }

        if (!$this->messageHandler->validateSignature($message, $issuer)) {
            throw new SamlException('Invalid signature');
        }
    }
}
