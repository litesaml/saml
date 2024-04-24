<?php

namespace Litesaml;

use DateTime;
use LightSaml\Binding\BindingFactory;
use LightSaml\Context\Profile\MessageContext;
use LightSaml\Credential\KeyHelper;
use LightSaml\Credential\X509Certificate;
use LightSaml\Helper;
use LightSaml\Model\Assertion\Assertion;
use LightSaml\Model\Assertion\Attribute;
use LightSaml\Model\Assertion\AttributeStatement;
use LightSaml\Model\Assertion\Issuer;
use LightSaml\Model\Protocol\AuthnRequest;
use LightSaml\Model\Protocol\LogoutRequest;
use LightSaml\Model\Protocol\LogoutResponse;
use LightSaml\Model\Protocol\Response as SamlAuthnResponse;
use LightSaml\Model\Protocol\SamlMessage;
use LightSaml\Model\Protocol\Status;
use LightSaml\Model\Protocol\StatusCode;
use LightSaml\Model\XmlDSig\SignatureWriter;
use LightSaml\SamlConstants;
use Litesaml\Models\Descriptors\Endpoint;
use Litesaml\Models\Descriptors\Idp;
use Litesaml\Models\Descriptors\Role;
use Litesaml\Models\Descriptors\Sp;
use Litesaml\Models\Messages\Message;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

trait ConcernsIssuer
{
    public function sendAuthnRequest(Sp $issuer, Idp $recipient): SymfonyResponse
    {
        $authnRequest = (new AuthnRequest())
            ->setAssertionConsumerServiceURL($issuer->acs->location)
            ->setProtocolBinding($issuer->acs->getBinding())
            ->setID(Helper::generateID())
            ->setIssueInstant(new DateTime())
            ->setDestination($recipient->sso->location)
            ->setIssuer(new Issuer($issuer->entityId));

        return $this->send($authnRequest, $issuer, $recipient->sso);
    }

    /**
     * @param \Litesaml\Models\Descriptors\Idp $issuer
     * @param \Litesaml\Models\Descriptors\Sp $recipient
     * @param \Litesaml\Models\Messages\Attribute[] $attributes
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function sendAuthnResponse(Idp $issuer, Sp $recipient, array $attributes): SymfonyResponse
    {
        $response = new SamlAuthnResponse();

        $response
            ->setStatus(
                new Status(
                    new StatusCode(SamlConstants::STATUS_SUCCESS),
                ),
            )
            ->setID(Helper::generateID())
            ->setIssueInstant(new DateTime())
            ->setDestination($recipient->acs->location)
            ->setIssuer(new Issuer($issuer->entityId));

        foreach ($attributes as $attribute) {
            $assertion = (new Assertion())
                ->setId(Helper::generateID())
                ->setIssueInstant(new DateTime())
                ->setIssuer($response->getIssuer())
                ->addItem(
                    (new AttributeStatement())
                        ->addAttribute(
                            new Attribute($attribute->name, $attribute->value)
                        ),
                );

            $response->addAssertion($assertion);
        }

        return $this->send($response, $issuer, $recipient->acs);
    }

    public function sendLogoutRequest(Role $issuer, Role $recipient): SymfonyResponse
    {
        $logoutRequest = (new LogoutRequest())
            ->setID(Helper::generateID())
            ->setIssueInstant(new DateTime())
            ->setDestination($recipient->slo->location)
            ->setIssuer(new Issuer($issuer->entityId));

        return $this->send($logoutRequest, $issuer, $recipient->slo);
    }

    public function sendLogoutResponse(Role $issuer, Role $recipient): SymfonyResponse
    {
        $response = (new LogoutResponse())
            ->setStatus(
                new Status(
                    new StatusCode(SamlConstants::STATUS_SUCCESS),
                ),
            )
            ->setID(Helper::generateID())
            ->setIssueInstant(new DateTime())
            ->setDestination($recipient->slo->location)
            ->setIssuer(new Issuer($issuer->entityId));

        return $this->send($response, $issuer, $recipient->slo);
    }

    private function send(SamlMessage $message, Role $issuer, Endpoint $endpoint): SymfonyResponse
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

            $message->setSignature(
                new SignatureWriter($certificate, $privateKey)
            );
        }

        return $binding->send($messageContext);
    }
}
