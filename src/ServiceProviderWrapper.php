<?php

namespace Litesaml;

use DateTime;
use LightSaml\Context\Model\DeserializationContext;
use LightSaml\Context\Model\SerializationContext;
use LightSaml\Credential\X509Certificate;
use LightSaml\Helper;
use LightSaml\Model\Assertion\EncryptedAssertionReader;
use LightSaml\Model\Assertion\Issuer;
use LightSaml\Model\Assertion\NameID;
use LightSaml\Model\Metadata\AssertionConsumerService;
use LightSaml\Model\Metadata\EntityDescriptor;
use LightSaml\Model\Metadata\KeyDescriptor;
use LightSaml\Model\Metadata\SingleLogoutService;
use LightSaml\Model\Metadata\SpSsoDescriptor;
use LightSaml\Model\Protocol as LightSaml;
use LightSaml\Model\Protocol\AuthnRequest as LightSamlAuthnRequest;
use LightSaml\Model\Protocol\LogoutRequest as LightSamlLogoutRequest;
use LightSaml\Model\Protocol\LogoutResponse as LightSamlLogoutResponse;
use LightSaml\Model\Protocol\Status as LightSamlStatus;
use LightSaml\Model\Protocol\StatusCode;
use LightSaml\SamlConstants;
use Litesaml\Enums\BindingType;
use Litesaml\Enums\Status;
use Litesaml\Exceptions\SamlException;
use Litesaml\Models\Descriptors\Certificate;
use Litesaml\Models\Descriptors\Endpoint;
use Litesaml\Models\Descriptors\Idp;
use Litesaml\Models\Descriptors\PublicKey;
use Litesaml\Models\Descriptors\Role;
use Litesaml\Models\Descriptors\Sp;
use Litesaml\Models\Messages\Attribute;
use Litesaml\Models\Messages\AuthnRequest;
use Litesaml\Models\Messages\AuthnResponse;
use Litesaml\Models\Messages\LogoutRequest;
use Litesaml\Models\Messages\LogoutResponse;
use Litesaml\Models\Messages\Message;
use Litesaml\Support\MessageHandler;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class ServiceProviderWrapper
{
    public function __construct(
        private Sp $sp,
        private MessageHandler $messageHandler,
    ) {
    }

    public static function parseMetadata(string $xml): Idp
    {
        $entityDescriptor = EntityDescriptor::loadXml($xml);

        $idpDescriptor = $entityDescriptor->getFirstIdpSsoDescriptor();
        if (!$idpDescriptor) {
            throw new SamlException('No IdP SSO descriptor found in metadata');
        }

        $ssoService = $idpDescriptor->getFirstSingleSignOnService();
        if (!$ssoService?->getLocation() || !$ssoService->getBinding()) {
            throw new SamlException('No SSO service found in IdP metadata');
        }

        $sloService = $idpDescriptor->getFirstSingleLogoutService();
        if (!$sloService?->getLocation() || !$sloService->getBinding()) {
            throw new SamlException('No SLO service found in IdP metadata');
        }

        $signing = null;
        foreach ($idpDescriptor->getAllKeyDescriptors() ?? [] as $keyDescriptor) {
            if ($keyDescriptor->getUse() === KeyDescriptor::USE_SIGNING && $keyDescriptor->getCertificate()) {
                $signing = new Certificate(publicKey: new PublicKey($keyDescriptor->getCertificate()->getData()));
                break;
            }
        }

        return new Idp(
            entityId: $entityDescriptor->getEntityID(),
            sso: new Endpoint($ssoService->getLocation(), BindingType::fromUrn($ssoService->getBinding())),
            slo: new Endpoint($sloService->getLocation(), BindingType::fromUrn($sloService->getBinding())),
            signing: $signing,
        );
    }

    public function generateMetadata(): string
    {
        $spSsoDescriptor = new SpSsoDescriptor();

        if ($this->sp->signing) {
            $cert = (new X509Certificate())->loadPem($this->sp->signing->publicKey->toPem());
            $spSsoDescriptor->addKeyDescriptor(new KeyDescriptor(KeyDescriptor::USE_SIGNING, $cert));
        }

        if ($this->sp->encryption) {
            $cert = (new X509Certificate())->loadPem($this->sp->encryption->publicKey->toPem());
            $spSsoDescriptor->addKeyDescriptor(new KeyDescriptor(KeyDescriptor::USE_ENCRYPTION, $cert));
        }

        $spSsoDescriptor->addAssertionConsumerService(
            (new AssertionConsumerService())
                ->setBinding($this->sp->acs->getBinding())
                ->setLocation($this->sp->acs->location)
        );

        $spSsoDescriptor->addSingleLogoutService(
            (new SingleLogoutService())
                ->setBinding($this->sp->slo->getBinding())
                ->setLocation($this->sp->slo->location)
        );

        $entityDescriptor = (new EntityDescriptor($this->sp->entityId))
            ->addItem($spSsoDescriptor);

        $context = new SerializationContext();
        $entityDescriptor->serialize($context->getDocument(), $context);

        return (string) $context->getDocument()->saveXML();
    }

    public function sendAuthnRequest(Idp $recipient, ?string $relayState = null): ResponseInterface
    {
        $authnRequest = (new LightSamlAuthnRequest())
            ->setAssertionConsumerServiceURL($this->sp->acs->location)
            ->setProtocolBinding($this->sp->acs->getBinding())
            ->setID(Helper::generateID())
            ->setIssueInstant(new DateTime())
            ->setDestination($recipient->sso->location)
            ->setIssuer(new Issuer($this->sp->entityId))
            ->setRelayState($relayState);

        return $this->messageHandler->send($authnRequest, $this->sp, $recipient->sso);
    }

    public function handleAuthnResponse(ServerRequestInterface $request, bool $validate = false, ?Role $issuer = null): AuthnResponse
    {
        $message = $this->messageHandler->unpack($request);

        if (!$message instanceof LightSaml\Response) {
            throw new SamlException('Wrong request received');
        }

        $attributes = [];
        $nameId = null;

        foreach ($message->getAllAssertions() as $assertion) {
            if ($nameId === null) {
                $nameId = $assertion->getSubject()?->getNameID()?->getValue();
            }

            foreach ($assertion->getAllAttributeStatements() as $attributeStatement) {
                foreach ($attributeStatement->getAllAttributes() as $attribute) {
                    $attributes[] = new Attribute(
                        name: $attribute->getName(),
                        values: $attribute->getAllAttributeValues() ?? [],
                    );
                }
            }
        }

        foreach ($message->getAllEncryptedAssertions() as $encryptedAssertion) {
            if (!$encryptedAssertion instanceof EncryptedAssertionReader) {
                continue;
            }

            if ($this->sp->encryption === null || $this->sp->encryption->privateKey === null) {
                throw new SamlException('No encryption certificate configured to decrypt assertion');
            }

            $key = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, ['type' => 'private']);
            $key->loadKey($this->sp->encryption->privateKey->toPem());

            $assertion = $encryptedAssertion->decryptAssertion($key, new DeserializationContext());

            if ($nameId === null) {
                $nameId = $assertion->getSubject()?->getNameID()?->getValue();
            }

            foreach ($assertion->getAllAttributeStatements() as $attributeStatement) {
                foreach ($attributeStatement->getAllAttributes() as $attribute) {
                    $attributes[] = new Attribute(
                        name: $attribute->getName(),
                        values: $attribute->getAllAttributeValues() ?? [],
                        encrypted: true,
                    );
                }
            }
        }

        $statusUrn = $message->getStatus()?->getStatusCode()?->getValue();

        $dto = new AuthnResponse(
            id: $message->getID(),
            issuer: $message->getIssuer()->getValue(),
            signature: $this->messageHandler->extractSignature($message),
            attributes: $attributes,
            status: $statusUrn !== null ? Status::fromUrn($statusUrn) : null,
            nameId: $nameId,
            inResponseTo: $message->getInResponseTo(),
            relayState: $message->getRelayState(),
        );

        $this->validateIfRequested($dto, $validate, $issuer);

        return $dto;
    }

    public function handleAuthnRequest(ServerRequestInterface $request, bool $validate = false, ?Role $issuer = null): AuthnRequest
    {
        $message = $this->messageHandler->unpack($request);

        if (!$message instanceof LightSamlAuthnRequest) {
            throw new SamlException('Wrong request received');
        }

        $dto = new AuthnRequest(
            id: $message->getID(),
            issuer: $message->getIssuer()->getValue(),
            signature: $this->messageHandler->extractSignature($message),
            relayState: $message->getRelayState(),
        );

        $this->validateIfRequested($dto, $validate, $issuer);

        return $dto;
    }

    public function sendLogoutRequest(Role $recipient, string $nameId, ?string $relayState = null, ?string $sessionIndex = null): ResponseInterface
    {
        $logoutRequest = (new LightSamlLogoutRequest())
            ->setID(Helper::generateID())
            ->setIssueInstant(new DateTime())
            ->setDestination($recipient->slo->location)
            ->setIssuer(new Issuer($this->sp->entityId))
            ->setNameID(new NameID($nameId))
            ->setSessionIndex($sessionIndex)
            ->setRelayState($relayState);

        return $this->messageHandler->send($logoutRequest, $this->sp, $recipient->slo);
    }

    public function sendLogoutResponse(Role $recipient): ResponseInterface
    {
        $logoutResponse = (new LightSamlLogoutResponse())
            ->setStatus(new LightSamlStatus(new StatusCode(SamlConstants::STATUS_SUCCESS)))
            ->setID(Helper::generateID())
            ->setIssueInstant(new DateTime())
            ->setDestination($recipient->slo->location)
            ->setIssuer(new Issuer($this->sp->entityId));

        return $this->messageHandler->send($logoutResponse, $this->sp, $recipient->slo);
    }

    public function handleLogoutRequest(ServerRequestInterface $request, bool $validate = false, ?Role $issuer = null): LogoutRequest
    {
        $message = $this->messageHandler->unpack($request);

        if (!$message instanceof LightSamlLogoutRequest) {
            throw new SamlException('Wrong request received');
        }

        $dto = new LogoutRequest(
            id: $message->getID(),
            issuer: $message->getIssuer()->getValue(),
            signature: $this->messageHandler->extractSignature($message),
            nameId: $message->getNameID()->getValue(),
            sessionIndex: $message->getSessionIndex(),
            relayState: $message->getRelayState(),
        );

        $this->validateIfRequested($dto, $validate, $issuer);

        return $dto;
    }

    public function handleLogoutResponse(ServerRequestInterface $request, bool $validate = false, ?Role $issuer = null): LogoutResponse
    {
        $message = $this->messageHandler->unpack($request);

        if (!$message instanceof LightSamlLogoutResponse) {
            throw new SamlException('Wrong request received');
        }

        $dto = new LogoutResponse(
            id: $message->getID(),
            issuer: $message->getIssuer()->getValue(),
            signature: $this->messageHandler->extractSignature($message),
            relayState: $message->getRelayState(),
        );

        $this->validateIfRequested($dto, $validate, $issuer);

        return $dto;
    }

    public function validateSignature(Message $message, Role $issuer): bool
    {
        return $this->messageHandler->validateSignature($message, $issuer);
    }

    private function validateIfRequested(Message $dto, bool $validate, ?Role $issuer): void
    {
        if (!$validate) {
            return;
        }

        if ($issuer === null) {
            throw new SamlException('An issuer must be provided to validate the signature');
        }

        if (!$this->messageHandler->validateSignature($dto, $issuer)) {
            throw new SamlException('Invalid signature');
        }
    }
}
