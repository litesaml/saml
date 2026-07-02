<?php

namespace Litesaml\Support;

use Exception;
use LightSaml\Binding\BindingFactory;
use LightSaml\Context\Profile\MessageContext;
use LightSaml\Credential\KeyHelper;
use LightSaml\Credential\X509Certificate;
use LightSaml\Model\Protocol\SamlMessage;
use LightSaml\Model\XmlDSig\AbstractSignatureReader;
use LightSaml\Model\XmlDSig\SignatureStringReader;
use LightSaml\Model\XmlDSig\SignatureWriter;
use Litesaml\Exceptions\SamlException;
use Litesaml\Models\Descriptors\Endpoint;
use Litesaml\Models\Descriptors\Entity;
use Litesaml\Models\Messages\Message;
use Litesaml\Models\Messages\Signature;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;

final class MessageHandler
{
    public function __construct(
        private ResponseFactoryInterface $responseFactory,
        private StreamFactoryInterface $streamFactory,
    ) {
    }

    public function send(
        SamlMessage $message,
        Entity $issuer,
        Endpoint $endpoint,
    ): ResponseInterface {
        $messageContext = new MessageContext();
        $messageContext->setMessage($message);

        $bindingFactory = new BindingFactory(responseFactory: $this->responseFactory, streamFactory: $this->streamFactory);
        $binding = $bindingFactory->create($endpoint->getBinding());

        if ($issuer->signing) {
            $certificate = (new X509Certificate())->loadPem($issuer->signing->publicKey->toPem());
            $privateKey = KeyHelper::createPrivateKey(
                $issuer->signing->privateKey->toPem(),
                $issuer->signing->privateKey->passphrase
            );

            $message->setSignature(new SignatureWriter($certificate, $privateKey));
        }

        return $binding->send($messageContext);
    }

    public function unpack(ServerRequestInterface $request): SamlMessage
    {
        $bindingFactory = new BindingFactory();
        $binding = $bindingFactory->getBindingByRequest($request);

        $messageContext = new MessageContext();
        $binding->receive($request, $messageContext);

        $message = $messageContext->getMessage();

        if (!$message) {
            throw new SamlException('Message not found');
        }

        return $message;
    }

    public function extractSignature(SamlMessage $message): ?Signature
    {
        $signatureReader = $message->getSignature();

        if ($signatureReader instanceof SignatureStringReader) {
            return new Signature(
                value: $signatureReader->getSignature(),
                algorithm: $signatureReader->getAlgorithm(),
                data: $signatureReader->getData(),
            );
        }

        return null;
    }

    /**
     * Validates the signature of a received message against the issuer's signing certificate.
     *
     * Operates on the live LightSAML message so both bindings are covered: the detached
     * SignatureStringReader (HTTP-Redirect) and the enveloped SignatureXmlReader (HTTP-POST).
     * Delegating to the reader's own validate() is essential for POST — it runs LightSAML's XML
     * Signature Wrapping defense, which a flattened value/algorithm/data DTO cannot express.
     */
    public function validateMessageSignature(SamlMessage $message, Entity $issuer): bool
    {
        if (!$issuer->signing) {
            return false;
        }

        $signatureReader = $message->getSignature();

        if (!$signatureReader instanceof AbstractSignatureReader) {
            return false;
        }

        try {
            $key = KeyHelper::createPublicKey(
                (new X509Certificate())->loadPem($issuer->signing->publicKey->toPem())
            );

            return $signatureReader->validate($key);
        } catch (Exception) {
            return false;
        }
    }

    public function validateSignature(Message $message, Entity $issuer): bool
    {
        if (!$message->signature || !$issuer->signing) {
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

            return $signatureReader->validate($key);
        } catch (Exception) {
            return false;
        }
    }
}
