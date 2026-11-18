<?php
declare(strict_types=1);

namespace PdOidc\Oidc;

use InvalidArgumentException;
use League\OAuth2\Server\Entities\ClientEntityInterface;

final readonly class RegisteredClient implements ClientEntityInterface
{
    public const SCOPES = ['openid', 'profile', 'email'];

    public function __construct(
        private string $id,
        private string $name,
        private array $callbacks,
    ) {
        if (!preg_match('/\A[A-Za-z0-9][A-Za-z0-9_-]{0,190}\z/', $id)) {
            throw new InvalidArgumentException('Client IDs must use letters, digits, hyphens or underscores.');
        }
        if (!preg_match('/\A[^\p{C}]{1,160}\z/u', $name) || !array_is_list($callbacks)
            || $callbacks === [] || count($callbacks) > 20) {
            throw new InvalidArgumentException('Provide a client name and between one and twenty callback URLs.');
        }
        foreach ($callbacks as $callback) {
            if (!is_string($callback) || strlen($callback) > 2048 || !self::validCallback($callback)) {
                throw new InvalidArgumentException('Callback URLs must be absolute HTTPS URLs without user information or fragments.');
            }
        }
    }

    public function getIdentifier(): string
    {
        return $this->id;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getRedirectUri(): array
    {
        return $this->callbacks;
    }

    public function isConfidential(): bool
    {
        return false;
    }

    public function supportsGrantType(string $grantType): bool
    {
        return $grantType === 'authorization_code';
    }

    public function acceptsCallback(?string $callback): bool
    {
        return in_array($callback, $this->callbacks, true);
    }

    private static function validCallback(string $callback): bool
    {
        $url = parse_url($callback);
        if (filter_var($callback, FILTER_VALIDATE_URL) === false || ($url['scheme'] ?? null) !== 'https'
            || isset($url['user']) || isset($url['pass']) || isset($url['fragment'])
            || str_contains($callback, '\\')) {
            return false;
        }
        parse_str($url['query'] ?? '', $query);
        return array_intersect(['code', 'state', 'error', 'error_description'], array_keys($query)) === [];
    }
}
