<?php
declare(strict_types=1);

namespace PdOidc;

use RuntimeException;

final class Distribution
{
    private static ?array $defaults = null;

    public static function issuer(): string
    {
        $issuer = getenv('PD_OIDC_ISSUER') ?: (self::defaults()['issuer'] ?? 'http://127.0.0.1:3000');
        $url = parse_url($issuer);
        $local = ($url['scheme'] ?? null) === 'http'
            && in_array($url['host'] ?? null, ['localhost', '127.0.0.1', '[::1]'], true);
        if (filter_var($issuer, FILTER_VALIDATE_URL) === false
            || (!$local && ($url['scheme'] ?? null) !== 'https')
            || array_intersect(['user', 'pass', 'path', 'query', 'fragment'], array_keys($url ?: []))) {
            throw new RuntimeException('PD_OIDC_ISSUER must be a root HTTPS URL, or an HTTP loopback URL for development.');
        }
        return $issuer;
    }

    public static function theme(): string
    {
        return getenv('PD_THEME') ?: (self::defaults()['theme'] ?? 'standard');
    }

    public static function bootstrapClient(): ?array
    {
        return self::defaults()['legacy_client'] ?? null;
    }

    private static function defaults(): array
    {
        if (self::$defaults === null) {
            $file = dirname(__DIR__) . '/distribution/defaults.php';
            self::$defaults = is_file($file) ? require $file : [];
        }
        return self::$defaults;
    }
}
