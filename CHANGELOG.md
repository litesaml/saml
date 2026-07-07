<!--- BEGIN HEADER -->
# Changelog

All notable changes to this project will be documented in this file.
<!--- END HEADER -->

## 4.0.0 (2026-07-07)

### Breaking Changes

* Add first-class NameIDFormat support ([#9](https://github.com/litesaml/saml/pull/9))
* Consolidate optional send*/handle* parameters into ContextList ([#13](https://github.com/litesaml/saml/pull/13))

### Features

* Allow IdP to set NameID on sendAuthnResponse ([#11](https://github.com/litesaml/saml/pull/11))

## 3.0.1 (2026-07-07)

### Bug Fixes

* Require signature to cover the document root to close XSW bypass ([#10](https://github.com/litesaml/saml/pull/10))

## 3.0.0 (2026-07-02)

### Breaking Changes

* `validateSignature()` removed from `ServiceProviderWrapper` and `IdentityProviderWrapper` — signatures must now be validated inline via `handle*(validate: true, issuer: ...)`; there is no more after-the-fact validation on a returned DTO
* `Signature` class removed, and the `signature` property removed from all message DTOs (`Message`, `AuthnResponse`, `LogoutRequest`, etc.) — message DTOs are now pure parsed data with no signature accessor

### Bug Fixes

* Fix XML Signature Wrapping (XSW) vulnerability in POST-binding signature validation — `validateSignature()` flattened the enveloped `<ds:Signature>` into a `value`/`algorithm`/`data` DTO and verified a reconstructed detached signature, which never ran LightSAML's `assertNoXmlSignatureWrapping()` defense; an attacker holding one genuinely signed response could get forged attributes and NameID accepted as validated. Signatures are now verified against the live message via the reader's own `validate()` (`SignatureXmlReader` for POST, `SignatureStringReader` for Redirect), restoring the XSW check for both bindings

## 2.1.0 (2026-07-02)

### Features

* `AuthnResponse::$sessionIndex` — exposes the `SessionIndex` from the `AuthnStatement`, needed to send a `LogoutRequest`, without reading the low-level assertion manually

### Bug Fixes

* Validate signatures on HTTP-POST bound messages — `extractSignature()` only recognized detached signatures (`SignatureStringReader`) used by the Redirect binding; enveloped XML signatures carried by POST-bound messages were silently dropped and `validateSignature()` always threw "Invalid signature"

## 2.0.0 (2026-06-28)

### Breaking Changes

* `Role` renamed to `Entity` — all type hints referencing `Role` must be updated to `Entity`
* `ServiceProviderWrapper::parseMetadata()` removed — use `MetadataParser::parse()` instead

### Features

* `MetadataParser::parse()` — parses IdP metadata, SP metadata, and federation `EntitiesDescriptor` from a single entry point
* `EntityList` — typed wrapper returned when an `EntitiesDescriptor` contains multiple entities

### Tests

* Fixture-based coverage for single IdP, single SP, IdP list, SP list, and mixed IdP+SP federation metadata

## 1.0.1 (2026-06-28)

### Bug Fixes

* Remove unused imports in `ServiceProviderWrapperTest` — phpcs `no_unused_imports` rule was failing after tests were split into dedicated files

## 1.0.0 (2026-06-27)

### Breaking Changes

* `Attribute::$values` is now `string[]` — all attribute values are returned as an array; consumers that expected a single string must be updated

### Features

* Encrypted assertion support — IdP can send encrypted assertions via `Attribute::$encrypted`, SP decrypts them automatically in `handleAuthnResponse()`
* Opt-in signature validation on all `handle*` methods via `$validate` and `$issuer` parameters on both wrappers
* `ServiceProviderWrapper::parseMetadata()` builds an `Idp` descriptor from raw XML metadata
* `generateMetadata()` on both `ServiceProviderWrapper` and `IdentityProviderWrapper`
* `AuthnResponse` now carries `status`, `nameId`, and `inResponseTo`
* `LogoutRequest` now carries `nameId` and `sessionIndex`
* RelayState forwarding in all `send*` and `handle*` methods

### Tests

* Line coverage raised to 99.46% — error paths, wrong message types, and edge cases fully covered

## 0.5.0 (2026-06-27)

### Breaking Changes

* `sendLogoutRequest()` now requires a `string $nameId` parameter on both wrappers — `LogoutRequest::$nameID` is a non-nullable typed property in lightsaml 5 and must be initialized before serialization

### Bug Fixes

* Build URI with query string in `makeGetRequest()` — `HttpRedirectBinding` reads `getUri()->getQuery()` (raw string), not parsed query params
* Move `$slo` to `Role` base class so `sendLogoutRequest()` / `sendLogoutResponse()` can accept any `Role` without accessing an undefined property

### Code Refactoring

* Replace `@var` cast + truthy check in `extractSignature()` with `instanceof` check — the previous `@var` hid the nullable type and made the null guard always-false according to PHPStan
* Add return and param type annotations to `Key::getHeaders()` and `TestCase` helper methods

### Styles

* Apply php-cs-fixer formatting

## 0.4.0 (2026-06-27)

### Breaking Changes

* Migrate to lightsaml 5.x with PSR-7 HTTP interfaces
* Replace Saml class and traits with dedicated `ServiceProviderWrapper` and `IdentityProviderWrapper`
* Replace DTOs with native PHP 8.2 readonly classes
* Inject `MessageHandler` into wrappers instead of PSR factories

### Tests

* Rewrite test suite with fixtures and full coverage

### Documentation

* Add README, CONTRIBUTING, CHANGELOG and LICENSE

### Continuous Integration

* Modernize CI workflows (checkout@v4, Composer cache, PHP 8.4/8.5 matrix)
* Add quality checks workflow (phpcs + phpstan)

## 0.3.2 (2024-04-25)

### Bug Fixes

* Attach signature if exists in all messages

## 0.3.1 (2024-04-25)

### Bug Fixes

* Certificate private key can be null

## 0.3.0 (2024-04-24)

### Features

* Issuer can sign message

## 0.2.1 (2024-04-23)

### Documentation

* Update Readme

## 0.2.0 (2024-04-23)

### Documentation

* Rename package to `litesaml/saml`

## 0.1.0 (2024-04-19)

### Features

* Initial release — wrap basic SAML 2.0 workflows (SP and IdP)
