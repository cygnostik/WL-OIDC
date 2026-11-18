<?php
declare(strict_types=1);

namespace PdOidc\Web;

use DomainException;
use InvalidArgumentException;
use Laminas\Diactoros\Response\RedirectResponse;
use PDO;
use PdOidc\Access\Role;
use PdOidc\Pilot\Account;
use PdOidc\Pilot\AccountLinks;
use PdOidc\Pilot\Accounts;
use PdOidc\Pilot\IdentityDirectory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

final class AccountPages
{
    private readonly AccountLinks $links;
    private readonly IdentityDirectory $directory;

    public function __construct(PDO $db)
    {
        $this->links = new AccountLinks($db);
        $this->directory = new IdentityDirectory($db);
    }

    public function handle(string $path, ServerRequestInterface $request, ?Account $account, string $address): ResponseInterface
    {
        if (str_starts_with($path, '/admin')) {
            if ($account === null) {
                return new RedirectResponse('/', 303);
            }
            if (!$this->directory->isAdmin($account)) {
                return Page::render('message', ['title' => 'Access denied', 'message' => 'Identity administrator access is required.'], 403);
            }
        }

        $query = $request->getQueryParams();
        $form = null;
        if ($request->getMethod() === 'POST') {
            $form = $request->getParsedBody();
            if (!is_array($form) || !hash_equals($_SESSION['csrf'], self::field($form, 'csrf'))) {
                return Page::render('message', ['title' => 'Form expired', 'message' => 'Open the form again and try submitting it once more.'], 400);
            }
        }

        return match ($path) {
            '/create-account' => $this->signup($form, $address),
            '/password/forgot' => $this->forgot($form, $address),
            '/password/reset' => $this->reset($form),
            '/admin' => $this->admin($account, $query, $form),
            '/admin/user' => $this->user($account, $query, $form),
        };
    }

    private function signup(?array $form, string $address): ResponseInterface
    {
        if ($form === null) {
            return Page::render('signup');
        }
        $first = trim(self::field($form, 'first_name'));
        $last = trim(self::field($form, 'last_name'));
        $enteredEmail = trim(self::field($form, 'email'));
        $email = Accounts::normalizeEmail($enteredEmail);
        $note = trim(self::field($form, 'note'));
        if (!preg_match('/\A[^\p{C}]{1,80}\z/u', $first) || !preg_match('/\A[^\p{C}]{1,80}\z/u', $last)
            || $email === null || (mb_strlen($first) + mb_strlen($last) > 159)
            || !preg_match('/\A(?:[^\p{C}]|[\r\n\t]){1,1000}\z/u', $note)) {
            return Page::render('signup', compact('first', 'last', 'enteredEmail', 'note') + [
                'error' => 'Enter both names, a valid email address, and a note of up to 1,000 characters.',
            ], 422);
        }
        if ($this->links->allowRequest('signup', $email, $address)) {
            $this->directory->requestSignup($email, $first, $last, $note);
        }
        return self::notice('/create-account', 'Your request was submitted for review. Check your email for setup instructions if an administrator approves it.');
    }

    private function forgot(?array $form, string $address): ResponseInterface
    {
        if ($form === null) {
            return Page::render('forgot');
        }
        $email = Accounts::normalizeEmail(self::field($form, 'email'));
        if ($email !== null && $this->links->allowRequest('recovery', $email, $address)) {
            $this->links->requestRecovery($email);
        }
        return self::notice('/password/forgot', 'If an eligible account exists for that address, you’ll receive an email with instructions.');
    }

    private function reset(?array $form): ResponseInterface
    {
        if ($form !== null && self::field($form, 'action') === 'open') {
            unset($_SESSION['account_link']);
            $hash = $this->links->open(trim(self::field($form, 'code')));
            if ($hash === null) {
                return self::notice('/password/reset', 'This link is invalid, expired, or already used. You can request a new link.');
            }
            $_SESSION['account_link'] = $hash;
            return new RedirectResponse('/password/reset', 303);
        }

        $hash = $_SESSION['account_link'] ?? '';
        $purpose = $hash === '' ? null : $this->links->purpose($hash);
        if ($purpose === null) {
            unset($_SESSION['account_link']);
            return Page::render('reset', ['purpose' => null], $form === null ? 200 : 400);
        }
        if ($form === null) {
            return Page::render('reset', ['purpose' => $purpose]);
        }
        $password = self::field($form, 'password');
        $confirm = self::field($form, 'confirm');
        try {
            if (self::field($form, 'action') !== 'save' || !hash_equals($password, $confirm)) {
                throw new InvalidArgumentException('Enter the same password in both fields.');
            }
            if (!$this->links->redeem($hash, $password)) {
                unset($_SESSION['account_link']);
                return self::notice('/password/reset', 'This link is invalid, expired, or already used. You can request a new link.');
            }
        } catch (InvalidArgumentException $error) {
            return Page::render('reset', ['purpose' => $purpose, 'error' => $error->getMessage()], 422);
        }

        $_SESSION = [];
        if (!session_regenerate_id(true)) {
            throw new RuntimeException('Could not rotate the browser session.');
        }
        return self::notice('/', $purpose === 'activate' ? 'Your account is ready. Sign in with your new password.' : 'Password updated. Sign in with your new password.');
    }

    private function admin(Account $actor, array $query, ?array $form): ResponseInterface
    {
        if ($form !== null) {
            try {
                $decision = self::field($form, 'decision');
                if (!in_array($decision, ['approve', 'decline'], true)) {
                    throw new DomainException('Choose Approve or Decline.');
                }
                $approve = $decision === 'approve';
                $this->directory->decide(
                    $actor, self::identifier($form, 'id'), $approve,
                    self::field($form, 'service'), self::role($form, 'assigned_role'),
                );
                return self::notice('/admin', $approve ? 'Request approved. The account setup email is queued.' : 'Request declined.');
            } catch (DomainException $error) {
                return self::notice('/admin', $error->getMessage());
            }
        }
        $search = mb_substr(trim(self::field($query, 'q')), 0, 200);
        $page = max(1, min(10000, (int) self::field($query, 'page')));
        $requestPage = max(1, min(10000, (int) self::field($query, 'requests')));
        return Page::render('admin', $this->directory->overview($search, $page, $requestPage) + compact('search', 'page', 'requestPage'));
    }

    private function user(Account $actor, array $query, ?array $form): ResponseInterface
    {
        try {
            $subject = self::identifier($query, 'subject');
            if ($form !== null) {
                $changes = [];
                $access = $form['access'] ?? [];
                $roles = $form['service_role'] ?? [];
                if (!is_array($access) || !is_array($roles) || array_keys($access) !== array_keys($roles)) {
                    throw new DomainException('Review the service policy fields and submit them again.');
                }
                foreach ($access as $clientId => $setting) {
                    $clientId = (string) $clientId;
                    $override = match ($setting) {
                        'inherit' => null, 'allow' => true, 'deny' => false,
                        default => throw new DomainException('Choose a valid service access override.'),
                    };
                    $role = $roles[$clientId] === 'inherit' ? null : self::role($roles, $clientId);
                    $changes[$clientId] = [$override, $role];
                }
                $enabled = match (self::field($form, 'status')) {
                    'enabled' => true, 'disabled' => false,
                    default => throw new DomainException('Choose an account status.'),
                };
                $allServices = match (self::field($form, 'access_mode')) {
                    'all' => true, 'selected' => false,
                    default => throw new DomainException('Choose a default access setting.'),
                };
                $this->directory->updateUser($actor, $subject, $enabled, $allServices, self::role($form, 'default_role'), $changes);
                return self::notice('/admin/user?subject=' . $subject, 'Account settings saved.');
            }
        } catch (DomainException $error) {
            return self::notice(isset($subject) ? '/admin/user?subject=' . $subject : '/admin', $error->getMessage());
        }
        $user = $this->directory->user($subject);
        return $user === null
            ? Page::render('message', ['title' => 'Account not found', 'message' => 'Choose an account in the user manager.'], 404)
            : Page::render('admin-user', $user);
    }

    private static function field(array $input, string $name): string
    {
        return is_string($input[$name] ?? null) ? $input[$name] : '';
    }

    private static function identifier(array $input, string $name): string
    {
        $value = self::field($input, $name);
        if (!preg_match('/\A[a-f0-9]{32}\z/', $value)) {
            throw new DomainException('Choose a valid account or signup request.');
        }
        return $value;
    }

    private static function role(array $input, string $name): Role
    {
        return Role::tryFrom(self::field($input, $name)) ?? throw new DomainException('Choose a valid role.');
    }

    private static function notice(string $path, string $message): RedirectResponse
    {
        $_SESSION['notice'] = $message;
        return new RedirectResponse($path, 303);
    }
}
