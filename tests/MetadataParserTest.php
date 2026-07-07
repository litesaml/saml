<?php

namespace Tests;

use Litesaml\Enums\BindingType;
use Litesaml\Exceptions\SamlException;
use Litesaml\Models\Descriptors\EntityList;
use Litesaml\Models\Descriptors\Idp;
use Litesaml\Models\Descriptors\Sp;
use Litesaml\Support\MetadataParser;
use PHPUnit\Framework\Attributes\Test;

class MetadataParserTest extends TestCase
{
    #[Test]
    public function can_parse_idp_metadata(): void
    {
        $idp = MetadataParser::parse(file_get_contents(__DIR__ . '/fixtures/idp_metadata.xml'));

        $this->assertInstanceOf(Idp::class, $idp);
        $this->assertEquals('https://idp.localhost', $idp->entityId);
        $this->assertEquals('https://idp.localhost/sso', $idp->sso->location);
        $this->assertEquals(BindingType::REDIRECT, $idp->sso->binding);
        $this->assertEquals('https://idp.localhost/slo', $idp->slo->location);
        $this->assertEquals(BindingType::REDIRECT, $idp->slo->binding);
        $this->assertNotNull($idp->signing);
        $this->assertEquals([
            'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        ], $idp->nameIdFormats);
    }

    #[Test]
    public function can_parse_sp_metadata(): void
    {
        $sp = MetadataParser::parse(file_get_contents(__DIR__ . '/fixtures/sp_metadata.xml'));

        $this->assertInstanceOf(Sp::class, $sp);
        $this->assertEquals('https://sp.localhost', $sp->entityId);
        $this->assertEquals('https://sp.localhost/acs', $sp->acs->location);
        $this->assertEquals(BindingType::POST, $sp->acs->binding);
        $this->assertEquals('https://sp.localhost/slo', $sp->slo->location);
        $this->assertEquals(BindingType::REDIRECT, $sp->slo->binding);
        $this->assertNotNull($sp->signing);
        $this->assertEquals([
            'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        ], $sp->nameIdFormats);
    }

    #[Test]
    public function can_parse_idp_list_metadata(): void
    {
        $list = MetadataParser::parse(file_get_contents(__DIR__ . '/fixtures/idp_list_metadata.xml'));

        $this->assertInstanceOf(EntityList::class, $list);
        $this->assertCount(2, $list->entities);
        $this->assertContainsOnlyInstancesOf(Idp::class, $list->entities);
        $this->assertEquals('https://idp1.localhost', $list->entities[0]->entityId);
        $this->assertEquals('https://idp2.localhost', $list->entities[1]->entityId);
    }

    #[Test]
    public function can_parse_sp_list_metadata(): void
    {
        $list = MetadataParser::parse(file_get_contents(__DIR__ . '/fixtures/sp_list_metadata.xml'));

        $this->assertInstanceOf(EntityList::class, $list);
        $this->assertCount(2, $list->entities);
        $this->assertContainsOnlyInstancesOf(Sp::class, $list->entities);
        $this->assertEquals('https://sp1.localhost', $list->entities[0]->entityId);
        $this->assertEquals('https://sp2.localhost', $list->entities[1]->entityId);
    }

    #[Test]
    public function can_parse_mixed_list_metadata(): void
    {
        $list = MetadataParser::parse(file_get_contents(__DIR__ . '/fixtures/mixed_list_metadata.xml'));

        $this->assertInstanceOf(EntityList::class, $list);
        $this->assertCount(2, $list->entities);
        $this->assertInstanceOf(Idp::class, $list->entities[0]);
        $this->assertInstanceOf(Sp::class, $list->entities[1]);
        $this->assertEquals('https://idp.localhost', $list->entities[0]->entityId);
        $this->assertEquals('https://sp.localhost', $list->entities[1]->entityId);
    }

    #[Test]
    public function parse_throws_without_any_sso_descriptor(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('No SSO descriptor found in metadata');

        MetadataParser::parse('<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"/>');
    }

    #[Test]
    public function parse_throws_without_sso_service(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('No SSO service found in IdP metadata');

        MetadataParser::parse(
            '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x">'
            . '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>'
            . '</md:EntityDescriptor>'
        );
    }

    #[Test]
    public function parse_throws_without_slo_service(): void
    {
        $this->expectException(SamlException::class);
        $this->expectExceptionMessage('No SLO service found in IdP metadata');

        MetadataParser::parse(
            '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x">'
            . '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            . '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.localhost/sso"/>'
            . '</md:IDPSSODescriptor>'
            . '</md:EntityDescriptor>'
        );
    }
}
