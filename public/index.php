<?php
declare(strict_types=1);

use Laminas\Diactoros\Response;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\Diactoros\ServerRequestFilter\DoNotFilter;
use League\OAuth2\Server\Exception\OAuthServerException;
use PdOidc\Oidc\Provider;
use PdOidc\Pilot\Accounts;
use PdOidc\Web\BrowserSignIn;
use PdOidc\Web\Page;

require dirname(__DIR__) . '/vendor/autoload.php';

header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');

$path = '';
try {
    $request = ServerRequestFactory::fromGlobals(requestFilter: new DoNotFilter());
    $path = $request->getUri()->getPath();
    header('Content-Security-Policy: ' . Page::securityPolicy(reset: $path === '/password/reset'));
    $methods = match ($path) {
        '/', '/account', '/oauth2/authorize', '/.well-known/openid-configuration',
        '/.well-known/openid-configuration/', '/oidc/jwks' => ['GET'],
        '/login', '/logout', '/oauth2/token' => ['POST'],
        '/oidc/userinfo', '/create-account', '/password/forgot', '/password/reset', '/admin', '/admin/user' => ['GET', 'POST'],
        default => [],
    };
    if ($methods === []) {
        $response = new JsonResponse(['error' => 'not_found'], 404);
    } elseif (!in_array($request->getMethod(), $methods, true)) {
        $response = new JsonResponse(['error' => 'method_not_allowed'], 405, ['Allow' => implode(', ', $methods)]);
    } else {
        $accounts = Accounts::fromEnvironment();
        $response = match ($path) {
            '/.well-known/openid-configuration', '/.well-known/openid-configuration/' =>
                new JsonResponse(Provider::fromEnvironment($accounts)->discovery()),
            '/oidc/jwks' => new JsonResponse(Provider::fromEnvironment($accounts)->jwks()),
            '/oauth2/token' => Provider::fromEnvironment($accounts)->token($request),
            '/oidc/userinfo' => Provider::fromEnvironment($accounts)->userinfo($request),
            default => (new BrowserSignIn($accounts))->handle($path, $request),
        };
    }
} catch (OAuthServerException $error) {
    $response = $error->generateHttpResponse(new Response());
} catch (Throwable $error) {
    error_log('PD-OIDC request failed on ' . $path . ' (' . get_class($error) . ')');
    $response = new JsonResponse(['error' => 'server_error'], 500);
}

http_response_code($response->getStatusCode());
foreach ($response->getHeaders() as $name => $values) {
    foreach ($values as $index => $value) {
        header("$name: $value", $index === 0);
    }
}
echo $response->getBody();
