<?php
declare(strict_types=1);

namespace PdOidc\Oidc;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use LogicException;

final class IdTokenResponse extends BearerTokenResponse
{
    public function __construct(private readonly string $issuer, private readonly SigningKey $signingKey)
    {
    }

    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        if (!$accessToken instanceof AccessToken) {
            throw new LogicException('Unexpected token type');
        }
        $subject = $accessToken->getUserIdentifier() ?? throw new LogicException('Missing token subject');
        $claims = $accessToken->idClaims();
        unset($claims['sub']);
        $claims['at_hash'] = SigningKey::base64Url(substr(hash('sha256', $accessToken->toString(), true), 0, 16));
        return ['id_token' => $this->signingKey->signIdToken(
            $this->issuer,
            $accessToken->getClient()->getIdentifier(),
            $subject,
            $accessToken->getExpiryDateTime(),
            $claims,
        )];
    }
}
