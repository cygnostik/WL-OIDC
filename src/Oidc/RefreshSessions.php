<?php
declare(strict_types=1);

namespace PdOidc\Oidc;

use PDO;
use SensitiveParameter;

final class RefreshSessions
{
    public const MAX_DAYS = 365;

    public function __construct(private readonly PDO $db) {}

    public function setDays(string $client, int $days, bool $bootstrap = false): void
    {
        $sql = 'INSERT INTO pd_oidc_login_policies (client_id, days) VALUES (?, ?)';
        $sql .= $bootstrap ? ' ON DUPLICATE KEY UPDATE client_id = pd_oidc_login_policies.client_id'
            : ' ON DUPLICATE KEY UPDATE generation = generation + (days > ?), days = ?';
        $this->db->prepare($sql)->execute($bootstrap ? [$client, $days] : [$client, $days, $days, $days]);
    }

    public function start(string $client, string $subject, int $version, int $authTime, array $scopes): ?string
    {
        $policy = $this->policy($client);
        if ($policy === null || !$policy['days']) {
            return null;
        }
        $id = bin2hex(random_bytes(16));
        $statement = $this->db->prepare(<<<'SQL'
            INSERT INTO pd_oidc_refresh_sessions
                (id, client_id, subject, session_version, policy_generation, auth_time, scopes, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            SQL);
        $statement->execute([$id, $client, $subject, $version, $policy['generation'], $authTime, implode(' ', $scopes),
            time() + (int) $policy['days'] * 86400]);
        return $this->newToken($id);
    }

    public function find(#[SensitiveParameter] string $token, ?string $client): ?array
    {
        if (!preg_match('/\A[a-f0-9]{64}\z/', $token)) {
            return null;
        }
        $select = $this->db->prepare(<<<'SQL'
            SELECT s.*, t.token_hash, t.spent FROM pd_oidc_refresh_tokens t
            JOIN pd_oidc_refresh_sessions s ON s.id = t.session_id WHERE t.token_hash = ? FOR UPDATE
            SQL);
        $select->execute([hash('sha256', $token)]);
        $row = $select->fetch();
        return $row && ($client === null || $row['client_id'] === $client) ? $row : null;
    }

    public function canRenew(array $session): bool
    {
        if ($session['revoked'] || (int) $session['expires_at'] <= time()) {
            return false;
        }
        if ($session['spent']) {
            $this->revoke($session['id']);
            return false;
        }
        $policy = $this->policy($session['client_id']);
        return $policy !== null && (int) $policy['days'] > 0
            && (int) $policy['generation'] === (int) $session['policy_generation'];
    }

    public function rotate(array $session): string
    {
        $this->db->prepare('UPDATE pd_oidc_refresh_tokens SET spent = TRUE WHERE token_hash = ?')
            ->execute([$session['token_hash']]);
        return $this->newToken($session['id']);
    }

    public function revoke(string $id): void
    {
        $this->db->prepare('UPDATE pd_oidc_refresh_sessions SET revoked = TRUE WHERE id = ?')->execute([$id]);
    }

    public function prune(): int
    {
        $delete = $this->db->prepare('DELETE FROM pd_oidc_refresh_sessions WHERE expires_at <= ? ORDER BY expires_at LIMIT 1000');
        $delete->execute([time()]);
        return $delete->rowCount();
    }

    private function policy(string $client): ?array
    {
        $query = $this->db->prepare('SELECT days, generation FROM pd_oidc_login_policies WHERE client_id = ? LOCK IN SHARE MODE');
        $query->execute([$client]);
        return $query->fetch() ?: null;
    }

    private function newToken(string $id): string
    {
        $token = bin2hex(random_bytes(32));
        $this->db->prepare('INSERT INTO pd_oidc_refresh_tokens (token_hash, session_id) VALUES (?, ?)')
            ->execute([hash('sha256', $token), $id]);
        return $token;
    }
}
