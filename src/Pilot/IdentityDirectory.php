<?php
declare(strict_types=1);

namespace PdOidc\Pilot;

use DomainException;
use PDO;
use PdOidc\Access\Role;
use PdOidc\Oidc\RefreshSessions;
use RuntimeException;
use Throwable;

final class IdentityDirectory
{
    public function __construct(private readonly PDO $db) {}

    public function isAdmin(Account $actor): bool
    {
        $query = $this->db->prepare(<<<'SQL'
            SELECT 1 FROM pd_identity_admins i JOIN pd_accounts a ON a.subject = i.subject
            WHERE a.subject = ? AND a.enabled = TRUE AND a.email_verified = TRUE AND a.session_version = ?
            SQL);
        $query->execute([$actor->subject, $actor->sessionVersion]);
        return (bool) $query->fetchColumn();
    }

    public function requestSignup(string $email, string $first, string $last, string $note): void
    {
        $insert = $this->db->prepare(<<<'SQL'
            INSERT INTO pd_signup_requests (id, email, first_name, last_name, note, created_at)
            SELECT ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM pd_accounts WHERE email = ?)
            ON DUPLICATE KEY UPDATE id = pd_signup_requests.id
            SQL);
        $insert->execute([bin2hex(random_bytes(16)), $email, $first, $last, $note, time(), $email]);
    }

    public function overview(string $query, int $page, int $requestPage): array
    {
        $users = $this->db->prepare(<<<'SQL'
            SELECT subject, email, display_name, enabled, email_verified, default_role, allow_all_services
            FROM pd_accounts WHERE INSTR(email, ?) > 0 OR INSTR(display_name, ?) > 0
            ORDER BY email LIMIT 31 OFFSET ?
            SQL);
        $users->bindValue(1, $query);
        $users->bindValue(2, $query);
        $users->bindValue(3, ($page - 1) * 30, PDO::PARAM_INT);
        $users->execute();
        $requests = $this->db->prepare('SELECT * FROM pd_signup_requests ORDER BY created_at, id LIMIT 31 OFFSET ?');
        $requests->bindValue(1, ($requestPage - 1) * 30, PDO::PARAM_INT);
        $requests->execute();
        return ['users' => $users->fetchAll(), 'requests' => $requests->fetchAll(), 'services' => $this->services()];
    }

    public function user(string $subject): ?array
    {
        $query = $this->db->prepare(<<<'SQL'
            SELECT a.subject, a.email, a.display_name, a.enabled, a.email_verified, a.allow_all_services, a.default_role,
                   i.subject IS NOT NULL AS identity_admin
            FROM pd_accounts a LEFT JOIN pd_identity_admins i ON a.subject = i.subject WHERE a.subject = ?
            SQL);
        $query->execute([$subject]);
        $account = $query->fetch();
        if (!$account) {
            return null;
        }
        $query = $this->db->prepare(<<<'SQL'
            SELECT s.client_id, c.display_name, s.enabled, s.requires_operator, o.access_override, o.role_override
            FROM pd_services s JOIN pd_oidc_clients c USING (client_id)
            LEFT JOIN pd_service_overrides o ON o.client_id = s.client_id AND o.subject = ?
            ORDER BY s.client_id
            SQL);
        $query->execute([$subject]);
        return ['user' => $account, 'services' => $query->fetchAll()];
    }

    public function decide(Account $actor, string $requestId, bool $approve, string $clientId, Role $role): void
    {
        $this->change($actor, function () use ($actor, $requestId, $approve, $clientId, $role): void {
            $select = $this->db->prepare('SELECT * FROM pd_signup_requests WHERE id = ? FOR UPDATE');
            $select->execute([$requestId]);
            $request = $select->fetch();
            if (!$request) {
                throw new DomainException('This signup request has already been reviewed.');
            }
            $subject = $requestId;
            if ($approve) {
                if ($clientId !== '') {
                    $this->requireService($clientId, true);
                }
                $existing = $this->db->prepare('SELECT 1 FROM pd_accounts WHERE email = ? FOR UPDATE');
                $existing->execute([$request['email']]);
                if ($existing->fetchColumn()) {
                    throw new DomainException('An account already exists for this email. Decline the request and manage the existing account.');
                }
                $subject = bin2hex(random_bytes(16));
                $insert = $this->db->prepare(<<<'SQL'
                    INSERT INTO pd_accounts (subject, email, display_name, password_hash, allow_all_services)
                    VALUES (?, ?, ?, ?, FALSE)
                    SQL);
                $insert->execute([
                    $subject, $request['email'], $request['first_name'] . ' ' . $request['last_name'],
                    Accounts::hashNewPassword(bin2hex(random_bytes(32))),
                ]);
                if ($clientId !== '') {
                    $this->saveOverride($subject, $clientId, true, $role);
                }
                (new AccountLinks($this->db))->issue($subject, 0, 'activate');
            }
            $this->db->prepare('DELETE FROM pd_signup_requests WHERE id = ?')->execute([$requestId]);
            $this->audit($actor, $approve ? 'signup.approve' : 'signup.decline', $subject);
        });
    }

    public function updateUser(
        Account $actor,
        string $subject,
        bool $enabled,
        bool $allServices,
        Role $role,
        array $serviceChanges,
    ): void {
        $this->change($actor, function () use ($actor, $subject, $enabled, $allServices, $role, $serviceChanges): void {
            $query = $this->db->prepare('SELECT enabled FROM pd_accounts WHERE subject = ? FOR UPDATE');
            $query->execute([$subject]);
            $current = $query->fetch();
            if (!$current) {
                throw new DomainException('This account was not found.');
            }
            if ($current['enabled'] && !$enabled) {
                $admin = $this->db->prepare('SELECT 1 FROM pd_identity_admins WHERE subject = ? LOCK IN SHARE MODE');
                $admin->execute([$subject]);
                if ($admin->fetchColumn()) {
                    throw new DomainException('Remove identity administration access through the deployment CLI before disabling this account.');
                }
                $this->db->prepare('DELETE FROM pd_account_links WHERE subject = ?')->execute([$subject]);
            }
            $update = $this->db->prepare(<<<'SQL'
                UPDATE pd_accounts SET session_version = session_version + IF(enabled AND ? = 0, 1, 0),
                    enabled = ?, allow_all_services = ?, default_role = ? WHERE subject = ?
                SQL);
            $update->execute([(int) $enabled, (int) $enabled, (int) $allServices, $role->value, $subject]);
            foreach ($serviceChanges as $clientId => [$access, $override]) {
                $this->requireService($clientId);
                $this->saveOverride($subject, $clientId, $access, $override);
            }
            $this->audit($actor, 'user.update', $subject);
        });
    }

    public function setLoginDays(Account $actor, string $clientId, int $days): void
    {
        if ($days < 0 || $days > RefreshSessions::MAX_DAYS) {
            throw new DomainException('Use a session duration from 0 to ' . RefreshSessions::MAX_DAYS . ' days.');
        }
        $this->change($actor, function () use ($actor, $clientId, $days): void {
            $this->requireService($clientId);
            (new RefreshSessions($this->db))->setDays($clientId, $days);
            $this->audit($actor, 'service.login_days', $clientId);
        });
    }

    private function services(): array
    {
        return $this->db->query('SELECT client_id, display_name, enabled, requires_operator, COALESCE(p.days, 0) AS login_days'
            . ' FROM pd_services JOIN pd_oidc_clients USING (client_id)'
            . ' LEFT JOIN pd_oidc_login_policies p USING (client_id) ORDER BY display_name, client_id')->fetchAll();
    }

    private function requireService(string $clientId, bool $enabledOnly = false): void
    {
        $query = $this->db->prepare('SELECT enabled FROM pd_services JOIN pd_oidc_clients USING (client_id) WHERE client_id = ? LOCK IN SHARE MODE');
        $query->execute([$clientId]);
        $service = $query->fetch();
        if (!$service || ($enabledOnly && !$service['enabled'])) {
            throw new DomainException('Choose an available service.');
        }
    }

    private function saveOverride(string $subject, string $clientId, ?bool $access, ?Role $role): void
    {
        if ($access === null && $role === null) {
            $this->db->prepare('DELETE FROM pd_service_overrides WHERE subject = ? AND client_id = ?')->execute([$subject, $clientId]);
            return;
        }
        $statement = $this->db->prepare(<<<'SQL'
            INSERT INTO pd_service_overrides (subject, client_id, access_override, role_override) VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE access_override = ?, role_override = ?
            SQL);
        $accessValue = $access === null ? null : (int) $access;
        $statement->execute([$subject, $clientId, $accessValue, $role?->value, $accessValue, $role?->value]);
    }

    private function change(Account $actor, callable $operation): void
    {
        $this->db->beginTransaction();
        try {
            $query = $this->db->prepare(<<<'SQL'
                SELECT 1 FROM pd_accounts a JOIN pd_identity_admins i ON i.subject = a.subject
                WHERE a.subject = ? AND a.enabled = TRUE AND a.email_verified = TRUE AND a.session_version = ?
                FOR UPDATE
                SQL);
            $query->execute([$actor->subject, $actor->sessionVersion]);
            if (!$query->fetchColumn()) {
                throw new DomainException('Identity administrator access is required.');
            }
            $operation();
            $this->db->commit();
        } catch (Throwable $error) {
            $this->db->rollBack();
            throw $error;
        }
    }

    private function audit(Account $actor, string $operation, string $target): void
    {
        $stmt = $this->db->prepare('INSERT INTO pd_identity_audit (actor, operation, target, created_at) VALUES (?, ?, ?, ?)');
        $stmt->execute([$actor->subject, $operation, $target, time()]);
    }
}
