<?php
declare(strict_types=1);

namespace PdOidc\Web;

use Laminas\Diactoros\Response\HtmlResponse;

final class Page
{
    public static function render(string $view, array $data = [], int $status = 200): HtmlResponse
    {
        $theme = Theme::current();
        $brand = ['name' => $theme->name, 'logo' => $theme->logo];
        $assetPath = $theme->path;
        $escape = static fn(string $text): string => htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $csrf = $_SESSION['csrf'];
        $notice = $_SESSION['notice'] ?? '';
        unset($_SESSION['notice']);
        ob_start();
        try {
            require dirname(__DIR__, 2) . '/views/layout.php';
            $html = ob_get_contents();
        } finally {
            ob_end_clean();
        }
        return new HtmlResponse($html, $status);
    }

    public static function securityPolicy(?string $callback = null, bool $reset = false): string
    {
        $form = "'self'";
        if ($callback !== null) {
            $uri = parse_url($callback);
            if (($uri['scheme'] ?? null) === 'https' && preg_match('/\A(?:[A-Za-z0-9.-]+|\[[0-9a-f:]+\])\z/i', $uri['host'] ?? '')) {
                $form .= ' https://' . $uri['host'] . (isset($uri['port']) ? ':' . $uri['port'] : '');
            }
        }
        return "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; form-action "
            . $form . "; base-uri 'none'; frame-ancestors 'none'" . ($reset ? "; script-src 'self'" : '');
    }
}
