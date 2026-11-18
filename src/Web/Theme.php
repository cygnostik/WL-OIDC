<?php
declare(strict_types=1);

namespace PdOidc\Web;

use PdOidc\Distribution;
use RuntimeException;

final readonly class Theme
{
    private function __construct(public string $path, public string $name, public ?string $logo) {}

    public static function current(): self
    {
        $skin = Distribution::theme();
        if (!preg_match('/\A[a-z0-9][a-z0-9-]{0,63}\z/', $skin)) {
            throw new RuntimeException('Invalid PD_THEME name.');
        }
        $path = '/assets/themes/' . $skin;
        $files = dirname(__DIR__, 2) . '/public' . $path;
        if (!is_file($files . '/brand.json') || !is_file($files . '/theme.css')) {
            throw new RuntimeException('The selected theme needs brand.json and theme.css.');
        }
        $brand = json_decode(file_get_contents($files . '/brand.json'), true, flags: JSON_THROW_ON_ERROR);
        $name = $brand['name'] ?? null;
        $logo = $brand['logo'] ?? null;
        if (($brand['version'] ?? null) !== 1 || !is_string($name) || !preg_match('/\A[^\p{C}]{1,80}\z/u', $name)
            || ($logo !== null && (!is_string($logo) || !preg_match('/\A[A-Za-z0-9_-]+\.(?:svg|png|webp|jpe?g)\z/i', $logo)
                || !is_file($files . '/' . $logo)))) {
            throw new RuntimeException('Invalid theme manifest. Use version 1, a display name and an optional local image.');
        }
        return new self($path, $name, $logo);
    }
}
