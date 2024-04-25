<?php

namespace Litesaml;

use Exception;
use LightSaml\Credential\KeyHelper;
use LightSaml\Credential\X509Certificate;
use LightSaml\Model\Protocol as LightSaml;
use LightSaml\Binding\BindingFactory;
use LightSaml\Context\Profile\MessageContext;
use LightSaml\Model\XmlDSig\SignatureStringReader;
use Litesaml\Exceptions\SamlException;
use Litesaml\Models\Descriptors\Role;
use Litesaml\Models\Messages\Attribute;
use Litesaml\Models\Messages\AuthnRequest;
use Litesaml\Models\Messages\AuthnResponse;
use Litesaml\Models\Messages\LogoutRequest;
use Litesaml\Models\Messages\LogoutResponse;
use Litesaml\Models\Messages\Message;
use Litesaml\Models\Messages\Signature;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

trait ConcernsRecipient
{
    public function handleAuthnResponse(SymfonyRequest $request): AuthnResponse
    {
        $message = $this->unpack($request);

        if (! $message instanceof LightSaml\Response) {
            throw new SamlException('Wrong request received');
        }

        $attributes = [];

        foreach ($message->getAllAssertions() as $assertion) {
            foreach ($assertion->getAllAttributeStatements() as $attributeStatement) {
                foreach ($attributeStatement->getAllAttributes() as $attribute) {
                    $attributes[] = new Attribute(
                        name: $attribute->getName(),
                        value: $attribute->getFirstAttributeValue()
                    );
                }
            }
        }

        return new AuthnResponse(
            id: $message->getID(),
            issuer: $message->getIssuer()->getValue(),
            attributes: $attributes,
            signature: $this->extractSignature($message),
        );
    }

    public function handleAuthnRequest(SymfonyRequest $request): AuthnRequest
    {
        $message = $this->unpack($request);

        if (! $message instanceof LightSaml\AuthnRequest) {
            throw new SamlException('Wrong request received');
        }

        return new AuthnRequest(
            id: $message->getID(),
            issuer: $message->getIssuer()->getValue(),
            signature: $this->extractSignature($message),
        );
    }

    public function handleLogoutRequest(SymfonyRequest $request): LogoutRequest
    {
        $message = $this->unpack($request);

        if (! $message instanceof LightSaml\LogoutRequest) {
            throw new SamlException('Wrong request received');
        }

        return new LogoutRequest(
            id: $message->getID(),
            issuer: $message->getIssuer()->getValue(),
            signature: $this->extractSignature($message),
        );
    }

    public function handleLogoutResponse(SymfonyRequest $request): LogoutResponse
    {
        $message = $this->unpack($request);

        if (! $message instanceof LightSaml\LogoutResponse) {
            throw new SamlException('Wrong request received');
        }

        return new LogoutResponse(
            id: $message->getID(),
            issuer: $message->getIssuer()->getValue(),
            signature: $this->extractSignature($message),
        );
    }

    public function validateSignature(Message $message, Role $issuer): bool
    {
        if (! $message->signature || ! $issuer->signing) {
            return false;
        }

        try {
            $key = KeyHelper::createPublicKey(
                (new X509Certificate())->loadPem($issuer->signing->publicKey->toPem())
            );

            $signatureReader = new SignatureStringReader(
                $message->signature->value,
                $message->signature->algorithm,
                $message->signature->data,
            );

            if (! $signatureReader->validate($key)) {
                return false;
            }

            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    private function unpack(SymfonyRequest $request): LightSaml\SamlMessage
    {
        $bindingFactory = new BindingFactory();
        $binding = $bindingFactory->getBindingByRequest($request);

        $messageContext = new MessageContext();
        $binding->receive($request, $messageContext);

        $message = $messageContext->getMessage();

        if (! $message) {
            throw new SamlException('Message not found');
        }

        return $message;
    }

    private function extractSignature(LightSaml\SamlMessage $message): ?Signature
    {
        /** @var \LightSaml\Model\XmlDSig\SignatureStringReader $signatureReader */
        $signatureReader = $message->getSignature();

        if (! $signatureReader) {
            return null;
        }

        return new Signature(
            value: $signatureReader->getSignature(),
            algorithm: $signatureReader->getAlgorithm(),
            data: $signatureReader->getData()
        );
    }
}
