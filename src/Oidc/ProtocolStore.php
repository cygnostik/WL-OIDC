<?php
declare(strict_types=1);

namespace PdOidc\Oidc;

use DateTimeImmutable;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AuthCodeTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\ScopeTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use LogicException;
use PDO;
use PdOidc\Access\Role;
use PdOidc\Pilot\Account;
use PdOidc\Pilot\Accounts;

/**
 * One request's League callbacks and durable rows. Both code redemption and
 * authorization run inside transactions on the account policy connection.
 */
final class ProtocolStore implements
    AccessTokenRepositoryInterface,
    AuthCodeRepositoryInterface,
    ClientRepositoryInterface,
    RefreshTokenRepositoryInterface,
    ScopeRepositoryInterface
{
    private readonly PDO $pdo;
    private readonly ClientRegistry $clients;
    private readonly RefreshSessions $refresh;
    private ?array $authentication = null;
    private ?array $redeeming = null;

    public function __construct(private readonly Accounts $accounts)
    {
        $this->pdo = $accounts->connection();
        $this->clients = new ClientRegistry($this->pdo);
        $this->refresh = new RefreshSessions($this->pdo);
    }

    public function setAuthenticationContext(?string $nonce, int $authTime, int $sessionVersion): void
    {
        $this->authentication = ['nonce' => $nonce, 'auth_time' => $authTime, 'session_version' => $sessionVersion];
    }

    public function getClientEntity(string $clientIdentifier): ?RegisteredClient
    {
        return $this->clients->find($clientIdentifier);
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        return $clientSecret === null && $grantType === 'authorization_code' && $this->getClientEntity($clientIdentifier) !== null;
    }

    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        if (!in_array($identifier, RegisteredClient::SCOPES, true)) {
            return null;
        }

        return new class ($identifier) implements ScopeEntityInterface {
            use ScopeTrait;

            public function __construct(private readonly string $identifier)
            {
            }

            public function getIdentifier(): string
            {
                return $this->identifier;
            }
        };
    }

    public function finalizeScopes(
        array $scopes,
        string $grantType,
        ClientEntityInterface $clientEntity,
        ?string $userIdentifier = null,
        ?string $authCodeId = null,
    ): array {
        return $scopes;
    }

    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        return new class implements AuthCodeEntityInterface {
            use AuthCodeTrait;
            use EntityTrait;
            use TokenEntityTrait;
        };
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        $authentication = $this->authentication ?? throw new LogicException('Code is missing its authentication context');
        $statement = $this->pdo->prepare(
            'INSERT INTO pd_oidc_codes (id, subject, session_version, nonce, auth_time, expires_at)'
                . ' VALUES (?, ?, ?, ?, ?, ?)',
        );
        $statement->execute([
            $authCodeEntity->getIdentifier(),
            $authCodeEntity->getUserIdentifier(),
            $authentication['session_version'],
            $authentication['nonce'],
            $authentication['auth_time'],
            $authCodeEntity->getExpiryDateTime()->getTimestamp(),
        ]);
    }

    public function isAuthCodeRevoked(string $codeId): bool
    {
        if (!$this->pdo->inTransaction()) {
            throw new LogicException('Code redemption requires a transaction');
        }
        $statement = $this->pdo->prepare(
            'SELECT subject, session_version, nonce, auth_time FROM pd_oidc_codes'
                . ' WHERE id = ? AND consumed = FALSE AND expires_at > ? FOR UPDATE',
        );
        $statement->execute([$codeId, time()]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        $this->redeeming = $row === false ? null : $row;

        return $this->redeeming === null;
    }

    public function revokeAuthCode(string $codeId): void
    {
        $statement = $this->pdo->prepare('UPDATE pd_oidc_codes SET consumed = TRUE WHERE id = ? AND consumed = FALSE');
        $statement->execute([$codeId]);
        $this->redeeming = null;
        if ($statement->rowCount() !== 1) {
            throw OAuthServerException::invalidGrant();
        }
    }

    public function getNewToken(
        ClientEntityInterface $clientEntity,
        array $scopes,
        ?string $userIdentifier = null,
    ): AccessToken {
        $token = new AccessToken();
        $token->setClient($clientEntity);
        if ($userIdentifier !== null) {
            $token->setUserIdentifier($userIdentifier);
        }
        foreach ($scopes as $scope) {
            $token->addScope($scope);
        }
        return $token;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        // League calls this after validating the code binding and PKCE. The
        // isAuthCodeRevoked callback holds the code row locked until commit.
        $subject = $accessTokenEntity->getUserIdentifier();
        if (!$accessTokenEntity instanceof AccessToken || $subject === null
            || $this->redeeming === null || $this->redeeming['subject'] !== $subject) {
            throw new LogicException('Access token is missing its authorization code context');
        }
        $sessionVersion = (int) $this->redeeming['session_version'];
        $role = $this->accounts->effectiveRole(
            $subject,
            $accessTokenEntity->getClient()->getIdentifier(),
            lock: true,
            sessionVersion: $sessionVersion,
        );
        if ($role === null) {
            throw OAuthServerException::invalidGrant();
        }
        $account = $this->accounts->findBySubject($subject);
        if ($account === null) {
            throw OAuthServerException::invalidGrant();
        }

        $scopes = array_map(
            static fn(ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $accessTokenEntity->getScopes(),
        );
        $authTime = (int) $this->redeeming['auth_time'];
        $this->persistAccess($accessTokenEntity, $account, $role, $sessionVersion, $authTime, $scopes, $this->redeeming['nonce']);
        $accessTokenEntity->setRefreshToken($this->refresh->start(
            $accessTokenEntity->getClient()->getIdentifier(), $account->subject, $sessionVersion, $authTime, $scopes,
        ));
    }

    public function renew(
        #[\SensitiveParameter] string $refreshToken,
        ?string $clientId,
        ?string $scope,
        int $accessLifetime,
    ): ?AccessToken {
        $session = $this->refresh->find($refreshToken, $clientId);
        if ($session === null || !$this->refresh->canRenew($session)) {
            return null;
        }
        $client = $this->getClientEntity($session['client_id']);
        $subject = $session['subject'];
        $version = (int) $session['session_version'];
        $role = $client === null ? null : $this->accounts->effectiveRole($subject, $session['client_id'],
            lock: true, sessionVersion: $version);
        $account = $role === null ? null : $this->accounts->findBySubject($subject);
        if ($account === null) {
            $this->refresh->revoke($session['id']);
            return null;
        }

        $original = explode(' ', $session['scopes']);
        $scopes = $scope === null ? $original : array_unique(explode(' ', $scope));
        if (!in_array('openid', $scopes, true) || array_diff($scopes, $original) !== []) {
            throw OAuthServerException::invalidScope('scope');
        }
        $entities = array_map(fn(string $name): ScopeEntityInterface => $this->getScopeEntityByIdentifier($name), $scopes);
        $token = $this->getNewToken($client, $entities, $subject);
        $token->setIdentifier(bin2hex(random_bytes(40)));
        $token->setExpiryDateTime((new DateTimeImmutable())->setTimestamp(min(time() + $accessLifetime, (int) $session['expires_at'])));
        $this->persistAccess($token, $account, $role, $version, (int) $session['auth_time'], $scopes);
        $token->setRefreshToken($this->refresh->rotate($session));
        return $token;
    }

    public function revokeRefreshSession(#[\SensitiveParameter] string $token, ?string $clientId): void
    {
        $session = $this->refresh->find($token, $clientId);
        if ($session !== null) {
            $this->refresh->revoke($session['id']);
        }
    }

    private function persistAccess(
        AccessToken $accessToken,
        Account $account,
        Role $role,
        int $sessionVersion,
        int $authTime,
        array $scopes,
        ?string $nonce = null,
    ): void {
        $profile = in_array('profile', $scopes, true);
        $email = in_array('email', $scopes, true);
        $claims = self::identityClaims($account, $profile, $email) + [
            'pd_role' => $role->value,
            'auth_time' => $authTime,
        ];
        if ($nonce !== null) {
            $claims['nonce'] = $nonce;
        }
        $accessToken->setIdClaims($claims);

        $statement = $this->pdo->prepare(
            'INSERT INTO pd_oidc_access_tokens (token_hash, subject, session_version, profile_scope, email_scope, expires_at)'
                . ' VALUES (?, ?, ?, ?, ?, ?)',
        );
        $tokenHash = hash('sha256', $accessToken->getIdentifier());
        $statement->execute([
            $tokenHash,
            $account->subject,
            $sessionVersion,
            (int) $profile,
            (int) $email,
            $accessToken->getExpiryDateTime()->getTimestamp(),
        ]);
        $this->pdo->prepare('INSERT INTO pd_oidc_access_token_clients (token_hash, client_id) VALUES (?, ?)')
            ->execute([$tokenHash, $accessToken->getClient()->getIdentifier()]);
    }

    public function revokeAccessToken(string $tokenId): void
    {
        $statement = $this->pdo->prepare('DELETE FROM pd_oidc_access_tokens WHERE token_hash = ?');
        $statement->execute([hash('sha256', $tokenId)]);
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        return $this->accessToken($tokenId) === null;
    }

    public function userinfo(#[\SensitiveParameter] string $tokenId): ?array
    {
        $token = $this->accessToken($tokenId);
        if ($token === null) {
            return null;
        }
        $sessionVersion = (int) $token['session_version'];
        if ($this->accounts->effectiveRole($token['subject'], $token['client_id'], sessionVersion: $sessionVersion) === null) {
            return null;
        }
        $account = $this->accounts->findBySubject($token['subject']);
        if ($account === null || !$account->enabled || !$account->emailVerified || $account->sessionVersion !== $sessionVersion) {
            return null;
        }
        return self::identityClaims($account, (bool) $token['profile_scope'], (bool) $token['email_scope']);
    }

    /** @return array{codes: int, access_tokens: int} */
    public function pruneExpired(): array
    {
        $now = time();
        $codes = $this->pdo->prepare('DELETE FROM pd_oidc_codes WHERE expires_at <= ? ORDER BY expires_at LIMIT 1000');
        $codes->execute([$now]);
        $tokens = $this->pdo->prepare('DELETE FROM pd_oidc_access_tokens WHERE expires_at <= ? ORDER BY expires_at LIMIT 1000');
        $tokens->execute([$now]);
        return ['codes' => $codes->rowCount(), 'access_tokens' => $tokens->rowCount()];
    }

    private function accessToken(#[\SensitiveParameter] string $tokenId): ?array
    {
        $statement = $this->pdo->prepare(
            'SELECT subject, session_version, profile_scope, email_scope, client_id FROM pd_oidc_access_tokens'
                . ' JOIN pd_oidc_access_token_clients USING (token_hash) WHERE token_hash = ? AND expires_at > ?',
        );
        $statement->execute([hash('sha256', $tokenId), time()]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : $row;
    }

    private static function identityClaims(Account $account, bool $includeProfile, bool $includeEmail): array
    {
        $claims = ['sub' => $account->subject];
        if ($includeProfile) {
            $claims['name'] = $account->name;
        }
        if ($includeEmail) {
            $claims['email'] = $account->email;
            $claims['email_verified'] = $account->emailVerified;
        }
        return $claims;
    }

    public function getNewRefreshToken(): ?RefreshTokenEntityInterface
    {
        return null;
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        throw new LogicException('Refresh tokens are disabled');
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        throw new LogicException('Refresh tokens are disabled');
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        return true;
    }
}
