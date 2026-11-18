<?php
declare(strict_types=1);

namespace PdOidc\Oidc;

use DateInterval;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\Response\RedirectResponse;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use LogicException;
use PdOidc\Distribution;
use PdOidc\Pilot\Accounts;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SensitiveParameter;
use Throwable;

final class Provider
{
    private const AUTHORIZATION_LIFETIME = 'PT2M';
    private const TOKEN_LIFETIME = 900;
    private const MAX_FORM_BYTES = 16_384;

    private readonly SigningKey $signingKey;
    private readonly ProtocolStore $store;
    private readonly AuthorizationServer $server;

    private function __construct(
        private readonly Accounts $accounts,
        private readonly string $issuer,
        #[SensitiveParameter] string $privateKey,
        #[SensitiveParameter] string $encryptionKey,
    ) {
        $this->signingKey = new SigningKey($privateKey);
        $this->store = new ProtocolStore($accounts);
        $this->server = new AuthorizationServer(
            $this->store,
            $this->store,
            $this->store,
            new CryptKey($privateKey),
            $encryptionKey,
            new IdTokenResponse($issuer, $this->signingKey),
        );
        $this->server->enableGrantType(
            new AuthCodeGrant($this->store, $this->store, new DateInterval(self::AUTHORIZATION_LIFETIME)),
            new DateInterval('PT' . self::TOKEN_LIFETIME . 'S'),
        );
    }

    public static function fromEnvironment(Accounts $accounts): self
    {
        $issuer = Distribution::issuer();

        $keyPath = getenv('PD_OIDC_PRIVATE_KEY_FILE');
        if ($keyPath === false || !is_file($keyPath) || !is_readable($keyPath)) {
            throw new RuntimeException('PD_OIDC_PRIVATE_KEY_FILE must point to a readable signing key');
        }
        $privateKey = file_get_contents($keyPath);
        if ($privateKey === false) {
            throw new RuntimeException('Failed to read the OIDC signing key');
        }
        $encryptionKey = base64_decode(getenv('PD_OIDC_ENCRYPTION_KEY') ?: '', true);
        if ($encryptionKey === false || strlen($encryptionKey) !== 32) {
            throw new RuntimeException('PD_OIDC_ENCRYPTION_KEY must contain 32 random bytes encoded as base64');
        }

        return new self($accounts, $issuer, $privateKey, $encryptionKey);
    }

    public function discovery(): array
    {
        return [
            'issuer' => $this->issuer,
            'authorization_endpoint' => $this->issuer . '/oauth2/authorize',
            'token_endpoint' => $this->issuer . '/oauth2/token',
            'revocation_endpoint' => $this->issuer . '/oauth2/revoke',
            'userinfo_endpoint' => $this->issuer . '/oidc/userinfo',
            'jwks_uri' => $this->issuer . '/oidc/jwks',
            'scopes_supported' => RegisteredClient::SCOPES,
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'token_endpoint_auth_methods_supported' => ['none'],
            'revocation_endpoint_auth_methods_supported' => ['none'],
            'code_challenge_methods_supported' => ['S256'],
            'claims_supported' => [
                'iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'at_hash',
                'name', 'email', 'email_verified', 'pd_role',
            ],
            'request_parameter_supported' => false,
            'request_uri_parameter_supported' => false,
        ];
    }

    public function jwks(): array
    {
        return ['keys' => [$this->signingKey->jwk()]];
    }

    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequestInterface
    {
        $query = $request->getQueryParams();
        self::validateParameters($request->getUri()->getQuery(), $query);
        $client = $this->store->getClientEntity($query['client_id'] ?? '');
        if ($client === null) {
            throw OAuthServerException::invalidClient($request);
        }
        $callback = $query['redirect_uri'] ?? null;
        if (!$client->acceptsCallback($callback)) {
            throw OAuthServerException::invalidRequest('redirect_uri');
        }
        $state = $query['state'] ?? null;
        if ($state !== null && !self::isVisibleAscii($state, 512)) {
            throw OAuthServerException::invalidRequest('state');
        }

        try {
            self::validateAuthorizationParameters($query);
            return $this->server->validateAuthorizationRequest($request);
        } catch (OAuthServerException $exception) {
            $redirect = self::callback($callback, $state === null ? [] : ['state' => $state]);
            throw new OAuthServerException(
                $exception->getMessage(),
                $exception->getCode(),
                $exception->getErrorType(),
                $exception->getHttpStatusCode(),
                $exception->getPayload()['hint'] ?? null,
                $redirect,
            );
        }
    }

    private static function validateAuthorizationParameters(array $query): void
    {
        if (($query['response_type'] ?? null) !== 'code') {
            throw new OAuthServerException('Only the code response type is supported.', 0, 'unsupported_response_type');
        }
        $scope = $query['scope'] ?? '';
        if (!in_array('openid', explode(' ', $scope), true)) {
            throw OAuthServerException::invalidScope('openid');
        }
        if (($query['code_challenge_method'] ?? null) !== 'S256') {
            throw OAuthServerException::invalidRequest('code_challenge_method');
        }
        if (!preg_match('/\A[A-Za-z0-9_-]{43}\z/', $query['code_challenge'] ?? '')) {
            throw OAuthServerException::invalidRequest('code_challenge');
        }
        if (isset($query['nonce']) && !self::isVisibleAscii($query['nonce'], 255)) {
            throw OAuthServerException::invalidRequest('nonce');
        }
        if (isset($query['prompt']) && !in_array($query['prompt'], ['none', 'login'], true)) {
            throw OAuthServerException::invalidRequest('prompt');
        }
        if (isset($query['max_age']) && !preg_match('/\A\d{1,9}\z/', $query['max_age'])) {
            throw OAuthServerException::invalidRequest('max_age');
        }
        if (($query['response_mode'] ?? 'query') !== 'query') {
            throw OAuthServerException::invalidRequest('response_mode');
        }
        foreach (['request', 'request_uri', 'claims'] as $parameter) {
            if (isset($query[$parameter])) {
                throw OAuthServerException::invalidRequest($parameter);
            }
        }
    }

    public function completeAuthorizationRequest(
        ServerRequestInterface $request,
        string $subject,
        int $authTime,
        int $sessionVersion,
    ): ResponseInterface {
        $authorization = $this->validateAuthorizationRequest($request);
        $query = $request->getQueryParams();
        return $this->transaction(function () use ($authorization, $query, $subject, $authTime, $sessionVersion): ResponseInterface {
            $client = $this->store->getClientEntity($authorization->getClient()->getIdentifier());
            if ($client === null || !$client->acceptsCallback($authorization->getRedirectUri())) {
                throw OAuthServerException::invalidRequest('redirect_uri');
            }
            $role = $this->accounts->effectiveRole($subject, $authorization->getClient()->getIdentifier(),
                lock: true, sessionVersion: $sessionVersion);
            if ($role === null) {
                return $this->authorizationError($authorization, 'access_denied');
            }
            $this->store->setAuthenticationContext($query['nonce'] ?? null, $authTime, $sessionVersion);
            $authorization->setUser(new class ($subject) implements UserEntityInterface {
                public function __construct(private readonly string $subject)
                {
                }

                public function getIdentifier(): string
                {
                    return $this->subject;
                }
            });
            $authorization->setAuthorizationApproved(true);
            return $this->server
                ->completeAuthorizationRequest($authorization, new Response())
                ->withHeader('Cache-Control', 'no-store');
        });
    }

    public function authorizationError(AuthorizationRequestInterface $authorization, string $error): ResponseInterface
    {
        $client = $authorization->getClient();
        $callback = $authorization->getRedirectUri();
        if (!$client instanceof RegisteredClient || !$client->acceptsCallback($callback)
            || !in_array($error, ['access_denied', 'login_required', 'interaction_required'], true)) {
            throw new LogicException('Invalid authorization error context');
        }
        $parameters = ['error' => $error];
        if ($authorization->getState() !== null) {
            $parameters['state'] = $authorization->getState();
        }
        return new RedirectResponse(self::callback($callback, $parameters), 302, ['Cache-Control' => 'no-store']);
    }

    public function token(ServerRequestInterface $request): ResponseInterface
    {
        if ($request->getMethod() !== 'POST') {
            return self::jsonError('invalid_request', 405, ['Allow' => 'POST']);
        }

        try {
            $form = self::publicClientForm($request);
            if (($form['grant_type'] ?? null) === 'refresh_token') {
                return $this->renew($form);
            }
            if (($form['grant_type'] ?? null) !== 'authorization_code') {
                throw OAuthServerException::unsupportedGrantType();
            }
            $client = $this->store->getClientEntity($form['client_id'] ?? '');
            if ($client === null) {
                throw OAuthServerException::invalidClient($request);
            }
            if (!$client->acceptsCallback($form['redirect_uri'] ?? null)) {
                throw OAuthServerException::invalidRequest('redirect_uri');
            }
            if (!preg_match('/\A[A-Za-z0-9_.~-]{43,128}\z/', $form['code_verifier'] ?? '')) {
                throw OAuthServerException::invalidRequest('code_verifier');
            }

            return $this->transaction(fn(): ResponseInterface =>
                $this->server->respondToAccessTokenRequest($request, new Response()));
        } catch (OAuthServerException $exception) {
            return $exception->generateHttpResponse(new Response())
                ->withHeader('Cache-Control', 'no-store')
                ->withHeader('Pragma', 'no-cache');
        }
    }

    public function revoke(ServerRequestInterface $request): ResponseInterface
    {
        $form = self::publicClientForm($request);
        if (!is_string($form['token'] ?? null) || $form['token'] === '') {
            throw OAuthServerException::invalidRequest('token');
        }
        return $this->transaction(function () use ($form): ResponseInterface {
            $this->store->revokeRefreshSession($form['token'], $form['client_id'] ?? null);
            return new Response();
        });
    }

    private function renew(#[SensitiveParameter] array $form): ResponseInterface
    {
        if (!isset($form['refresh_token']) || $form['refresh_token'] === '') {
            throw OAuthServerException::invalidRequest('refresh_token');
        }
        return $this->transaction(function () use ($form): ResponseInterface {
            // The opaque grant supplies the client binding for public clients omitting client_id.
            $token = $this->store->renew($form['refresh_token'], $form['client_id'] ?? null,
                $form['scope'] ?? null, self::TOKEN_LIFETIME);
            if ($token === null) {
                return self::jsonError('invalid_grant', 400, ['Pragma' => 'no-cache']);
            }
            $response = new IdTokenResponse($this->issuer, $this->signingKey);
            $response->setAccessToken($token);
            return $response->generateHttpResponse(new Response());
        });
    }

    private static function publicClientForm(ServerRequestInterface $request): array
    {
        $contentType = strtolower(trim(explode(';', $request->getHeaderLine('Content-Type'), 2)[0]));
        $form = $request->getParsedBody();
        if ($contentType !== 'application/x-www-form-urlencoded' || !is_array($form)) {
            throw OAuthServerException::invalidRequest('request');
        }
        $body = $request->getBody();
        if ($body->isSeekable()) {
            $body->rewind();
        }
        self::validateParameters($body->read(self::MAX_FORM_BYTES + 1), $form);
        if ($request->hasHeader('Authorization') || isset($form['client_secret'])
            || isset($form['client_assertion']) || isset($form['client_assertion_type'])) {
            throw OAuthServerException::invalidClient($request);
        }
        return $form;
    }

    public function userinfo(ServerRequestInterface $request): ResponseInterface
    {
        if (!in_array($request->getMethod(), ['GET', 'POST'], true)) {
            return self::jsonError('invalid_request', 405, ['Allow' => 'GET, POST']);
        }
        if (!preg_match('/\ABearer ([a-f0-9]{80})\z/i', $request->getHeaderLine('Authorization'), $match)) {
            return self::jsonError('invalid_token', 401, ['WWW-Authenticate' => 'Bearer error="invalid_token"']);
        }
        $claims = $this->store->userinfo($match[1]);
        return $claims === null
            ? self::jsonError('invalid_token', 401, ['WWW-Authenticate' => 'Bearer error="invalid_token"'])
            : new JsonResponse($claims, 200, ['Cache-Control' => 'no-store']);
    }

    private function transaction(callable $operation): ResponseInterface
    {
        $connection = $this->accounts->connection();
        $connection->beginTransaction();
        try {
            $response = $operation();
            $connection->commit();
            return $response;
        } catch (Throwable $exception) {
            if ($connection->inTransaction()) {
                $connection->rollBack();
            }
            throw $exception;
        }
    }

    private static function validateParameters(#[SensitiveParameter] string $raw, #[SensitiveParameter] array $parsed): void
    {
        if (strlen($raw) > self::MAX_FORM_BYTES || count($parsed) > 64) {
            throw OAuthServerException::invalidRequest('request');
        }
        $seen = [];
        foreach (explode('&', $raw) as $pair) {
            if ($pair === '') {
                continue;
            }
            $key = urldecode(explode('=', $pair, 2)[0]);
            if (!preg_match('/\A[A-Za-z0-9_-]+\z/', $key) || isset($seen[$key])) {
                throw OAuthServerException::invalidRequest('request');
            }
            $seen[$key] = true;
        }
        foreach ($parsed as $value) {
            if (!is_string($value)) {
                throw OAuthServerException::invalidRequest('request');
            }
        }
    }

    private static function isVisibleAscii(string $value, int $limit): bool
    {
        return strlen($value) <= $limit && preg_match('/\A[!-~]+\z/', $value) === 1;
    }

    private static function callback(string $uri, array $parameters): string
    {
        return $parameters === []
            ? $uri
            : $uri . (str_contains($uri, '?') ? '&' : '?') . http_build_query($parameters, encoding_type: PHP_QUERY_RFC3986);
    }

    private static function jsonError(string $error, int $status, array $headers = []): JsonResponse
    {
        return new JsonResponse(['error' => $error], $status, $headers + ['Cache-Control' => 'no-store']);
    }
}
