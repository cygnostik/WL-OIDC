<?php
declare(strict_types=1);

namespace PdOidc\Web;

use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;
use PdOidc\Distribution;
use PdOidc\Oidc\Provider;
use PdOidc\Pilot\Account;
use PdOidc\Pilot\Accounts;
use PdOidc\Pilot\IdentityDirectory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

final class BrowserSignIn
{
    private const FLOW_LIFETIME = 300;
    private const SESSION_LIFETIME = 28_800;

    public function __construct(private readonly Accounts $accounts)
    {
    }

    public function handle(string $path, ServerRequestInterface $request): ResponseInterface
    {
        $issuer = Distribution::issuer();
        $host = parse_url($issuer, PHP_URL_HOST);
        $local = parse_url($issuer, PHP_URL_SCHEME) === 'http'
            && in_array($host, ['127.0.0.1', 'localhost', '[::1]'], true);
        session_name($local ? 'pd_dev_session' : '__Host-pd_session');
        if (!session_start([
            'use_strict_mode' => true,
            'use_only_cookies' => true,
            'cookie_path' => '/',
            'cookie_secure' => !$local,
            'cookie_httponly' => true,
            'cookie_samesite' => 'Lax',
            'cache_limiter' => '',
        ])) {
            throw new RuntimeException('Could not open session');
        }

        $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
        $_SESSION['flows'] = array_filter(
            $_SESSION['flows'] ?? [],
            static fn(array $flow): bool => $flow['expires'] > time(),
        );
        return match ($path) {
            '/oauth2/authorize' => $this->authorize($request),
            '/login' => $this->login($request, $issuer),
            '/logout' => $this->logout($request),
            '/create-account', '/password/forgot', '/password/reset', '/admin', '/admin/user' =>
                (new AccountPages($this->accounts->connection()))->handle(
                    $path, $request, $this->sessionAccount(), $this->clientAddress($request),
                ),
            default => $this->account(),
        };
    }

    private function authorize(ServerRequestInterface $request): ResponseInterface
    {
        $provider = Provider::fromEnvironment($this->accounts);
        $authorization = $provider->validateAuthorizationRequest($request);
        $query = $request->getQueryParams();
        $account = $this->sessionAccount();
        $authTime = $_SESSION['auth_time'] ?? null;
        $prompt = $query['prompt'] ?? '';
        $maxAge = isset($query['max_age']) ? (int) $query['max_age'] : self::SESSION_LIFETIME;
        if ($account !== null && $authTime !== null && $prompt !== 'login'
            && $maxAge > 0 && time() - $authTime <= $maxAge) {
            return $provider->completeAuthorizationRequest($request, $account->subject, $authTime, $account->sessionVersion);
        }
        if ($prompt === 'none') {
            return $provider->authorizationError($authorization, 'login_required');
        }

        $flowId = bin2hex(random_bytes(16));
        $query = array_intersect_key($query, array_flip([
            'client_id', 'redirect_uri', 'response_type', 'scope', 'state', 'nonce',
            'code_challenge', 'code_challenge_method', 'response_mode', 'prompt', 'max_age',
        ]));
        $_SESSION['flows'][$flowId] = ['query' => $query, 'expires' => time() + self::FLOW_LIFETIME];
        $_SESSION['flows'] = array_slice($_SESSION['flows'], -8, null, true);
        return $this->page(flowId: $flowId);
    }

    private function login(ServerRequestInterface $request, string $issuer): ResponseInterface
    {
        $form = $request->getParsedBody();
        if (!is_array($form) || !$this->validCsrf($form)) {
            return $this->page(message: 'This sign-in form has expired. Open the sign-in page again.', status: 400);
        }
        $flowId = $form['flow'] ?? '';
        if (!is_string($flowId) || ($flowId !== '' && !isset($_SESSION['flows'][$flowId]))) {
            return $this->page(message: 'This sign-in request has expired. Start again from your project.', status: 400);
        }
        $email = $form['email'] ?? null;
        $password = $form['password'] ?? null;
        $account = is_string($email) && is_string($password)
            ? $this->accounts->authenticate($email, $password, $this->clientAddress($request))
            : null;
        if ($account === null) {
            return $this->page(flowId: $flowId, message: 'Unable to sign in with those credentials.', status: 401);
        }

        if (!session_regenerate_id(true)) {
            throw new RuntimeException('Could not rotate session ID');
        }
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
        $_SESSION['subject'] = $account->subject;
        $_SESSION['auth_time'] = time();
        $_SESSION['version'] = $account->sessionVersion;
        if ($flowId === '') {
            return new RedirectResponse('/account', 303);
        }

        $query = $_SESSION['flows'][$flowId]['query'];
        unset($_SESSION['flows'][$flowId]);
        $uri = $issuer . '/oauth2/authorize?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
        $authorizationRequest = (new ServerRequest(uri: $uri, method: 'GET'))->withQueryParams($query);
        $response = Provider::fromEnvironment($this->accounts)
            ->completeAuthorizationRequest($authorizationRequest, $account->subject, $_SESSION['auth_time'], $account->sessionVersion);
        return $response->withStatus(303);
    }

    private function account(): ResponseInterface
    {
        return $this->page(account: $this->sessionAccount());
    }

    private function sessionAccount(): ?Account
    {
        if (!isset($_SESSION['subject'], $_SESSION['auth_time'], $_SESSION['version'])) {
            return null;
        }
        if (time() - $_SESSION['auth_time'] < self::SESSION_LIFETIME) {
            $account = $this->accounts->findBySubject($_SESSION['subject']);
            if ($account !== null && $account->enabled && $account->emailVerified
                && $account->sessionVersion === $_SESSION['version']) {
                return $account;
            }
        }
        unset($_SESSION['auth_time'], $_SESSION['subject'], $_SESSION['version']);
        return null;
    }

    private function logout(ServerRequestInterface $request): ResponseInterface
    {
        $form = $request->getParsedBody();
        if (!is_array($form) || !$this->validCsrf($form)) {
            return $this->page(message: 'This form has expired. Open your account page again.', status: 400);
        }
        $_SESSION = [];
        if (!session_regenerate_id(true)) {
            throw new RuntimeException('Could not rotate session ID');
        }
        return new RedirectResponse('/', 303);
    }

    private function validCsrf(array $form): bool
    {
        return is_string($form['csrf'] ?? null) && hash_equals($_SESSION['csrf'], $form['csrf']);
    }

    private function clientAddress(ServerRequestInterface $request): string
    {
        $remote = $request->getServerParams()['REMOTE_ADDR'] ?? '';
        $trusted = preg_split('/[ ,]+/', trim(getenv('PD_TRUSTED_PROXY_IPS') ?: ''), flags: PREG_SPLIT_NO_EMPTY);
        $forwarded = $request->getHeaderLine('X-Forwarded-For');
        if (!in_array($remote, $trusted, true) || strlen($forwarded) > 1024) {
            return $remote;
        }
        foreach (array_reverse(explode(',', $forwarded)) as $hop) {
            $hop = trim($hop);
            if (!filter_var($hop, FILTER_VALIDATE_IP)) {
                return $remote;
            }
            if (!in_array($hop, $trusted, true)) {
                return $hop;
            }
        }
        return $remote;
    }

    private function page(
        ?Account $account = null,
        string $flowId = '',
        string $message = '',
        int $status = 200,
    ): ResponseInterface {
        $admin = $account !== null && (new IdentityDirectory($this->accounts->connection()))->isAdmin($account);
        $callback = $_SESSION['flows'][$flowId]['query']['redirect_uri'] ?? null;
        return Page::render('sign-in', compact('account', 'admin', 'flowId', 'message'), $status)
            ->withHeader('Content-Security-Policy', Page::securityPolicy($callback));
    }
}
