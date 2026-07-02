<?php

namespace Litesaml\Support;

use DOMElement;
use DOMXPath;
use Exception;
use LightSaml\Binding\BindingFactory;
use LightSaml\Context\Profile\MessageContext;
use LightSaml\Credential\KeyHelper;
use LightSaml\Credential\X509Certificate;
use LightSaml\Model\Protocol\SamlMessage;
use LightSaml\Model\XmlDSig\SignatureStringReader;
use LightSaml\Model\XmlDSig\SignatureWriter;
use LightSaml\Model\XmlDSig\SignatureXmlReader;
use Litesaml\Exceptions\SamlException;
use Litesaml\Models\Descriptors\Endpoint;
use Litesaml\Models\Descriptors\Entity;
use Litesaml\Models\Messages\Message;
use Litesaml\Models\Messages\Signature;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use RobRichards\XMLSecLibs\XMLSecurityDSig;

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

        if ($signatureReader instanceof SignatureXmlReader) {
            return $this->extractXmlSignature($signatureReader);
        }

        return null;
    }

    /**
     * HTTP-POST bindings carry an enveloped <ds:Signature> rather than a detached
     * signature over the query string, so it can't be read the same way as
     * SignatureStringReader. We flatten it to the same value/algorithm/data shape by
     * pulling the raw SignatureValue and re-canonicalizing SignedInfo ourselves (the
     * same inputs XMLSecurityDSig::verify() itself would use), so validateSignature()
     * can verify both binding types identically. This has to happen before the
     * reference/digest check below, because validateReference() detaches the
     * <ds:Signature> node from the document (per the enveloped-signature transform),
     * which would otherwise throw off the canonicalization. A digest failure means
     * the signed content was tampered with, so we treat it the same as no signature.
     */
    private function extractXmlSignature(SignatureXmlReader $signatureReader): ?Signature
    {
        $dsig = $signatureReader->getSignature();

        if (!$dsig instanceof XMLSecurityDSig || !$dsig->sigNode instanceof DOMElement) {
            return null;
        }

        $xpath = new DOMXPath($dsig->sigNode->ownerDocument);
        $xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
        $signatureValue = $xpath->evaluate('string(./ds:SignatureValue)', $dsig->sigNode);
        $signedInfo = (string) $dsig->canonicalizeSignedInfo();

        try {
            $dsig->validateReference();
        } catch (Exception) {
            return null;
        }

        return new Signature(
            value: $signatureValue,
            algorithm: $signatureReader->getAlgorithm(),
            data: $signedInfo,
        );
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
