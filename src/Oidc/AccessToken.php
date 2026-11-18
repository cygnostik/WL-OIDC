<?php
declare(strict_types=1);

namespace PdOidc\Oidc;

use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use LogicException;

final class AccessToken implements AccessTokenEntityInterface
{
    use EntityTrait;
    use TokenEntityTrait;

    private ?array $idClaims = null;

    public function setPrivateKey(#[\SensitiveParameter] CryptKeyInterface $privateKey): void
    {
        // This access token is opaque. Signing is confined to the ID token.
    }

    public function toString(): string
    {
        return $this->getIdentifier();
    }

    public function setIdClaims(array $claims): void
    {
        $this->idClaims = $claims;
    }

    public function idClaims(): array
    {
        return $this->idClaims ?? throw new LogicException('ID token claims were not resolved');
    }
}
