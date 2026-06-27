<!--- BEGIN HEADER -->
# Changelog

All notable changes to this project will be documented in this file.
<!--- END HEADER -->

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
