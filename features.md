# Features à implémenter

## 1. Métadonnées SP — génération (`generateSpMetadata`)

Nouvelle méthode exposant le XML de métadonnées du SP à partager avec l'IdP.

```php
$spFactory->generateMetadata(): string
```

S'appuie sur les modèles lightsaml-core : `EntityDescriptor`, `SpSsoDescriptor`, `KeyDescriptor`, `AssertionConsumerService`, `SingleLogoutService`.

---

## 2. Métadonnées IdP — parsing (`parseIdpMetadata`)

Parser le XML de métadonnées fourni par l'IdP pour construire automatiquement le descripteur `Idp`.

```php
$idpFactory->parseMetadata(string $xml): Idp
// ou fonction statique
IdentityProviderFactory::fromMetadata(string $xml): self
```

Utilise `EntityDescriptor::loadXml()` déjà disponible dans lightsaml-core.

---

## 3. `AuthnResponse` — NameID, statut et `isSuccess()`

Enrichir le DTO avec les champs manquants :
- `$nameId` — identifiant unique de l'utilisateur (`Subject->getNameID()`)
- `$status` — code statut de la réponse (`SamlConstants::STATUS_*`)
- `$inResponseTo` — corrélation avec la requête initiale
- `isSuccess(): bool`

---

## 4. RelayState — envoi et réception

- Paramètre optionnel `?string $relayState` dans `sendAuthnRequest()` et `sendLogoutRequest()`
- Propriété `?string $relayState` dans tous les DTOs de message

---

## 5. `LogoutRequest` — NameID et SessionIndex

Champs requis par la spec SAML 2.0, beaucoup d'IdPs rejettent les logout sans eux.

**Envoi** — ajouter les paramètres à `sendLogoutRequest()` sur `ServiceProviderWrapper` et `IdentityProviderWrapper` :

```php
$spWrapper->sendLogoutRequest(Role $recipient, string $nameId, ?string $sessionIndex = null): ResponseInterface
$idpWrapper->sendLogoutRequest(Role $recipient, string $nameId, ?string $sessionIndex = null): ResponseInterface
```

**Réception** — enrichir le DTO `LogoutRequest` et l'extraction dans `handleLogoutRequest()` :

```php
// DTO
class LogoutRequest extends Message {
    public readonly ?string $nameId;
    public readonly ?string $sessionIndex;
}

// handleLogoutRequest() extrait $message->getNameID()->getValue() et $message->getSessionIndex()
```

---

## 6. Attributs multi-valeurs

Utiliser `getAllAttributeValues()` au lieu de `getFirstAttributeValue()` lors du parsing de l'`AuthnResponse`. Le DTO `Attribute::$value` devient `array $values`.

---

## 7. Consolidation des assertions dans `sendAuthnResponse`

Créer une seule `Assertion` avec un `Subject` (bearer) et un `AttributeStatement` contenant tous les attributs, plutôt qu'une assertion par attribut.

---

## 8. Validation de signature intégrée (opt-in)

Paramètre optionnel dans les méthodes `handle*()` pour valider automatiquement la signature et lever une `SamlException` si invalide.

```php
$spFactory->handleAuthnResponse($request, validate: true)
```
