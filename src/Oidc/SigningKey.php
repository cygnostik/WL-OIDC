<?php
declare(strict_types=1);

namespace PdOidc\Oidc;

use DateTimeImmutable;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Builder;
use OpenSSLAsymmetricKey;
use RuntimeException;
use SensitiveParameter;

final class SigningKey
{
    private readonly InMemory $privateKey;
    private readonly array $publicJwk;

    public function __construct(#[SensitiveParameter] string $pem)
    {
        $key = openssl_pkey_get_private($pem);
        $details = $key instanceof OpenSSLAsymmetricKey ? openssl_pkey_get_details($key) : false;
        if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_RSA || $details['bits'] < 2048) {
            throw new RuntimeException('PD_OIDC_PRIVATE_KEY_FILE must contain an unencrypted RSA private key of at least 2048 bits');
        }
        $this->privateKey = InMemory::plainText($pem);
        $public = [
            'e' => self::base64Url($details['rsa']['e']),
            'kty' => 'RSA',
            'n' => self::base64Url($details['rsa']['n']),
        ];
        $thumbprint = hash('sha256', json_encode($public, JSON_THROW_ON_ERROR), true);
        $this->publicJwk = $public + ['kid' => self::base64Url($thumbprint), 'alg' => 'RS256', 'use' => 'sig'];
    }

    public function jwk(): array
    {
        return $this->publicJwk;
    }

    public function signIdToken(
        string $issuer,
        string $audience,
        string $subject,
        DateTimeImmutable $expiresAt,
        array $claims,
    ): string {
        $builder = Builder::new(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates())
            ->withHeader('kid', $this->publicJwk['kid'])
            ->issuedBy($issuer)
            ->permittedFor($audience)
            ->relatedTo($subject)
            ->issuedAt(new DateTimeImmutable())
            ->expiresAt($expiresAt);
        foreach ($claims as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }
        return $builder->getToken(new Sha256(), $this->privateKey)->toString();
    }

    public static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
