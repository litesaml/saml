<?php

namespace Litesaml\Support;

use DOMDocument;
use LightSaml\Model\Metadata\EntitiesDescriptor;
use LightSaml\Model\Metadata\EntityDescriptor;
use LightSaml\Model\Metadata\IdpSsoDescriptor;
use LightSaml\Model\Metadata\KeyDescriptor;
use LightSaml\Model\Metadata\SpSsoDescriptor;
use Litesaml\Enums\BindingType;
use Litesaml\Exceptions\SamlException;
use Litesaml\Models\Descriptors\Certificate;
use Litesaml\Models\Descriptors\Endpoint;
use Litesaml\Models\Descriptors\Entity;
use Litesaml\Models\Descriptors\EntityList;
use Litesaml\Models\Descriptors\Idp;
use Litesaml\Models\Descriptors\PublicKey;
use Litesaml\Models\Descriptors\Sp;

final class MetadataParser
{
    public static function parse(string $xml): Entity|EntityList
    {
        $doc = new DOMDocument();
        $doc->loadXML($xml);

        if ($doc->documentElement->localName === 'EntitiesDescriptor') {
            return new EntityList(array_map(
                fn (EntityDescriptor $ed) => self::parseEntityDescriptor($ed),
                EntitiesDescriptor::loadXml($xml)->getAllEntityDescriptors()
            ));
        }

        return self::parseEntityDescriptor(EntityDescriptor::loadXml($xml));
    }

    private static function parseEntityDescriptor(EntityDescriptor $entityDescriptor): Entity
    {
        $idpDescriptor = $entityDescriptor->getFirstIdpSsoDescriptor();
        if ($idpDescriptor) {
            return self::parseIdp($entityDescriptor, $idpDescriptor);
        }

        $spDescriptor = $entityDescriptor->getFirstSpSsoDescriptor();
        if ($spDescriptor) {
            return self::parseSp($entityDescriptor, $spDescriptor);
        }

        throw new SamlException('No SSO descriptor found in metadata');
    }

    private static function parseIdp(EntityDescriptor $entityDescriptor, IdpSsoDescriptor $idpDescriptor): Idp
    {
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

    private static function parseSp(EntityDescriptor $entityDescriptor, SpSsoDescriptor $spDescriptor): Sp
    {
        $acsService = $spDescriptor->getFirstAssertionConsumerService();
        if (!$acsService?->getLocation() || !$acsService->getBinding()) {
            throw new SamlException('No ACS service found in SP metadata');
        }

        $sloService = $spDescriptor->getFirstSingleLogoutService();
        if (!$sloService?->getLocation() || !$sloService->getBinding()) {
            throw new SamlException('No SLO service found in SP metadata');
        }

        $signing = null;
        $encryption = null;
        foreach ($spDescriptor->getAllKeyDescriptors() ?? [] as $keyDescriptor) {
            if ($keyDescriptor->getUse() === KeyDescriptor::USE_SIGNING && $keyDescriptor->getCertificate() && $signing === null) {
                $signing = new Certificate(publicKey: new PublicKey($keyDescriptor->getCertificate()->getData()));
            }
            if ($keyDescriptor->getUse() === KeyDescriptor::USE_ENCRYPTION && $keyDescriptor->getCertificate() && $encryption === null) {
                $encryption = new Certificate(publicKey: new PublicKey($keyDescriptor->getCertificate()->getData()));
            }
        }

        return new Sp(
            entityId: $entityDescriptor->getEntityID(),
            acs: new Endpoint($acsService->getLocation(), BindingType::fromUrn($acsService->getBinding())),
            slo: new Endpoint($sloService->getLocation(), BindingType::fromUrn($sloService->getBinding())),
            signing: $signing,
            encryption: $encryption,
        );
    }
}
