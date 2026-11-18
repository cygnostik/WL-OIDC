<?php
declare(strict_types=1);

namespace PdOidc\Pilot;

use PDO;
use PdOidc\Access\Role;
use PdOidc\Access\ServiceAccess;
use RuntimeException;
use Throwable;

final class Accounts
{
    private const WINDOW_SECONDS = 600;
    private const ACCOUNT_LIMIT = 8;
    private const NETWORK_LIMIT = 50;
    private const MAX_PASSWORD_BYTES = 1024;
    private const DUMMY_HASH = '$argon2id$v=19$m=65536,t=4,p=1$ckdLeFBJZzBHajZpaUE5aw$qG/wTpqAZPHAUh2VfaZDSXGOypXZ+/WJkUMSNT/OzSA';

    public function __construct(private readonly PDO $pdo) {}

    public static function fromEnvironment(): self
    {
        $dsn = getenv('PD_DB_DSN');
        $user = getenv('PD_DB_USER');
        $password = getenv('PD_DB_PASSWORD');
        if ($dsn === false || !str_starts_with($dsn, 'mysql:') || $user === false || $user === '' || $password === false) {
            throw new RuntimeException('Configure PD_DB_DSN, PD_DB_USER and PD_DB_PASSWORD.');
        }

        return new self(new PDO($dsn, $user, $password, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]));
    }

    public function connection(): PDO
    {
        return $this->pdo;
    }

    public static function normalizeEmail(string $email): ?string
    {
        $email = strtolower(trim($email));
        return strlen($email) <= 254 && filter_var($email, FILTER_VALIDATE_EMAIL) !== false ? $email : null;
    }

    public static function hashNewPassword(#[\SensitiveParameter] string $password): string
    {
        if (strlen($password) > self::MAX_PASSWORD_BYTES || preg_match('/\A.{15,}\z/us', $password) !== 1) {
            throw new \InvalidArgumentException('Use at least 15 characters and at most 1024 bytes for the password.');
        }

        return password_hash($password, PASSWORD_ARGON2ID);
    }

    public function findBySubject(string $subject): ?Account
    {
        if (!preg_match('/\A[a-f0-9]{32}\z/', $subject)) {
            return null;
        }
        $stmt = $this->pdo->prepare(<<<'SQL'
            SELECT subject, email, display_name, enabled, email_verified, session_version
            FROM pd_accounts WHERE subject = ?
            SQL);
        $stmt->execute([$subject]);
        $row = $stmt->fetch();
        return $row === false ? null : self::account($row);
    }

    public function effectiveRole(string $subject, string $clientId, bool $lock = false, ?int $sessionVersion = null): ?Role
    {
        if ($lock && !$this->pdo->inTransaction()) {
            throw new RuntimeException('A locked policy lookup requires an active transaction.');
        }
        if (!preg_match('/\A[a-f0-9]{32}\z/', $subject) || !preg_match('/\A[!-~]{1,191}\z/', $clientId)) {
            return null;
        }

        $sql = <<<'SQL'
            SELECT a.enabled AS user_enabled, a.email_verified, a.session_version, a.allow_all_services, a.default_role,
                   s.enabled AS service_enabled, s.requires_operator, o.access_override, o.role_override
            FROM pd_accounts AS a
            JOIN pd_services AS s ON s.client_id = ?
            LEFT JOIN pd_service_overrides AS o ON o.subject = a.subject AND o.client_id = s.client_id
            WHERE a.subject = ?
            SQL;
        $stmt = $this->pdo->prepare($sql . ($lock ? ' LOCK IN SHARE MODE' : ''));
        $stmt->execute([$clientId, $subject]);
        $row = $stmt->fetch();
        if ($row === false || !$row['email_verified'] || ($sessionVersion !== null && $sessionVersion !== (int) $row['session_version'])) {
            return null;
        }

        return ServiceAccess::effectiveRole(
            (bool) $row['user_enabled'],
            (bool) $row['service_enabled'],
            (bool) $row['allow_all_services'],
            Role::from($row['default_role']),
            $row['access_override'] === null ? null : (bool) $row['access_override'],
            $row['role_override'] === null ? null : Role::from($row['role_override']),
            (bool) $row['requires_operator'],
        );
    }

    public function authenticate(string $email, #[\SensitiveParameter] string $password, string $clientAddress): ?Account
    {
        if (strlen($password) > self::MAX_PASSWORD_BYTES) {
            return null;
        }

        if (random_int(1, 100) === 1) {
            $this->pruneLoginAttempts();
        }

        $window = intdiv(time(), self::WINDOW_SECONDS);
        $this->pdo->beginTransaction();
        try {
            $networkAllowed = $this->reserveAttempt('network:' . self::network($clientAddress), $window, self::NETWORK_LIMIT);
            $row = $networkAllowed ? $this->loginRecord(self::normalizeEmail($email)) : null;
            $accountAllowed = $row === null || $this->reserveAttempt('account:' . $row['subject'], $window, self::ACCOUNT_LIMIT);
            $this->pdo->commit();
        } catch (Throwable $error) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $error;
        }

        if (!$networkAllowed) {
            return null;
        }

        // Unknown and account-throttled addresses receive the same verification work.
        $hash = $accountAllowed ? ($row['password_hash'] ?? self::DUMMY_HASH) : self::DUMMY_HASH;
        $valid = password_verify($password, $hash);
        if (!$valid || !$accountAllowed || $row === null || !$row['enabled'] || !$row['email_verified']) {
            return null;
        }

        return self::account($row);
    }

    private function reserveAttempt(string $key, int $window, int $limit): bool
    {
        $bucket = hash('sha256', $key);
        $stmt = $this->pdo->prepare(<<<'SQL'
            INSERT INTO pd_login_attempts (bucket, window_id, attempts) VALUES (?, ?, 1)
            ON DUPLICATE KEY UPDATE attempts = IF(window_id >= ?, LEAST(attempts + 1, ?), 1),
                                    window_id = GREATEST(window_id, ?)
            SQL);
        $stmt->execute([$bucket, $window, $window, $limit + 1, $window]);
        $stmt = $this->pdo->prepare('SELECT attempts FROM pd_login_attempts WHERE bucket = ?');
        $stmt->execute([$bucket]);
        return (int) $stmt->fetchColumn() <= $limit;
    }

    private function loginRecord(?string $email): ?array
    {
        if ($email === null) {
            return null;
        }

        $stmt = $this->pdo->prepare(<<<'SQL'
            SELECT subject, email, display_name, enabled, email_verified, session_version, password_hash
            FROM pd_accounts WHERE email = ?
            SQL);
        $stmt->execute([$email]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    public static function network(string $address): string
    {
        $packed = inet_pton($address);
        if ($packed === false) {
            return 'unknown';
        }
        if (strlen($packed) === 4 || str_starts_with($packed, str_repeat("\0", 10) . "\xff\xff")) {
            return substr($packed, -4);
        }

        // Group IPv6 addresses by /64 so temporary interface addresses share a limit.
        return substr($packed, 0, 8);
    }

    private static function account(array $row): Account
    {
        return new Account(
            $row['subject'],
            $row['email'],
            $row['display_name'],
            (bool) $row['enabled'],
            (bool) $row['email_verified'],
            (int) $row['session_version'],
        );
    }

    private function pruneLoginAttempts(): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM pd_login_attempts WHERE window_id < ? LIMIT 1000');
        $stmt->execute([intdiv(time(), self::WINDOW_SECONDS) - 1]);
    }
}
