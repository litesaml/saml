<?php

namespace Litesaml\Support;

use Exception;
use LightSaml\Binding\BindingFactory;
use LightSaml\Context\Profile\MessageContext;
use LightSaml\Credential\KeyHelper;
use LightSaml\Credential\X509Certificate;
use LightSaml\Model\Protocol\SamlMessage;
use LightSaml\Model\XmlDSig\SignatureStringReader;
use LightSaml\Model\XmlDSig\SignatureWriter;
use Litesaml\Exceptions\SamlException;
use Litesaml\Models\Descriptors\Endpoint;
use Litesaml\Models\Descriptors\Role;
use Litesaml\Models\Messages\Message;
use Litesaml\Models\Messages\Signature;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

final class MessageHandler
{
    public static function send(SamlMessage $message, Role $issuer, Endpoint $endpoint): SymfonyResponse
    {
        $messageContext = new MessageContext();
        $messageContext->setMessage($message);

        $bindingFactory = new BindingFactory();
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

    public static function unpack(SymfonyRequest $request): SamlMessage
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

    public static function extractSignature(SamlMessage $message): ?Signature
    {
        /** @var SignatureStringReader $signatureReader */
        $signatureReader = $message->getSignature();

        if (!$signatureReader) {
            return null;
        }

        return new Signature(
            value: $signatureReader->getSignature(),
            algorithm: $signatureReader->getAlgorithm(),
            data: $signatureReader->getData(),
        );
    }

    public static function validateSignature(Message $message, Role $issuer): bool
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
