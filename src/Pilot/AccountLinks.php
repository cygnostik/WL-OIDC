<?php
declare(strict_types=1);

namespace PdOidc\Pilot;

use PDO;
use RuntimeException;
use SensitiveParameter;
use Throwable;

final class AccountLinks
{
    public function __construct(private readonly PDO $db) {}

    public function allowRequest(string $action, string $email, string $address): bool
    {
        $window = intdiv(time(), 3600);
        foreach ([
            [hash('sha256', $action . ':address:' . Accounts::network($address)), 24],
            [hash('sha256', $action . ':email:' . $email), 3],
        ] as [$bucket, $limit]) {
            $update = $this->db->prepare(<<<'SQL'
                INSERT INTO pd_public_attempts (bucket, window_id, attempts) VALUES (?, ?, 1)
                ON DUPLICATE KEY UPDATE attempts = IF(window_id = ?, LEAST(attempts + 1, ?), 1),
                                        window_id = GREATEST(window_id, ?)
                SQL);
            $update->execute([$bucket, $window, $window, $limit + 1, $window]);
            $select = $this->db->prepare('SELECT attempts FROM pd_public_attempts WHERE bucket = ?');
            $select->execute([$bucket]);
            if ((int) $select->fetchColumn() > $limit) {
                return false;
            }
        }
        return true;
    }

    public function requestRecovery(string $email): void
    {
        $this->db->beginTransaction();
        try {
            $select = $this->db->prepare('SELECT subject, email_verified, session_version FROM pd_accounts WHERE email = ? AND enabled = TRUE FOR UPDATE');
            $select->execute([$email]);
            if ($account = $select->fetch()) {
                $this->issue($account['subject'], (int) $account['session_version'], $account['email_verified'] ? 'reset' : 'activate');
            }
            $this->db->commit();
        } catch (Throwable $error) {
            $this->db->rollBack();
            throw $error;
        }
    }

    public function issue(string $subject, int $version, string $purpose): void
    {
        $token = bin2hex(random_bytes(32));
        $hash = hash('sha256', $token);
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $sealed = $nonce . sodium_crypto_secretbox($token, $nonce, self::mailKey());
        $link = $this->db->prepare('INSERT INTO pd_account_links (token_hash, subject, purpose, session_version, expires_at) VALUES (?, ?, ?, ?, ?)');
        $link->execute([$hash, $subject, $purpose, $version, time() + ($purpose === 'activate' ? 172800 : 2700)]);
        $mail = $this->db->prepare('INSERT INTO pd_account_mail (token_hash, sealed_token, next_attempt_at) VALUES (?, ?, ?)');
        $mail->execute([$hash, $sealed, time()]);
    }

    public function open(#[SensitiveParameter] string $token): ?string
    {
        if (!preg_match('/\A[a-f0-9]{64}\z/', $token)) {
            return null;
        }
        $hash = hash('sha256', $token);
        return $this->purpose($hash) === null ? null : $hash;
    }

    public function purpose(string $hash): ?string
    {
        $select = $this->db->prepare(<<<'SQL'
            SELECT l.purpose FROM pd_account_links l JOIN pd_accounts a ON a.subject = l.subject
            WHERE l.token_hash = ? AND l.expires_at > ? AND a.enabled = TRUE
                AND a.session_version = l.session_version AND (a.email_verified = (l.purpose = 'reset'))
            SQL);
        $select->execute([$hash, time()]);
        return $select->fetchColumn() ?: null;
    }

    public function redeem(string $hash, #[SensitiveParameter] string $password): bool
    {
        if ($this->purpose($hash) === null) {
            return false;
        }
        $passwordHash = Accounts::hashNewPassword($password);
        $select = $this->db->prepare('SELECT subject FROM pd_account_links WHERE token_hash = ?');
        $select->execute([$hash]);
        $subject = $select->fetchColumn();
        if ($subject === false) {
            return false;
        }
        $this->db->beginTransaction();
        try {
            $account = $this->db->prepare('SELECT enabled, email_verified, session_version FROM pd_accounts WHERE subject = ? FOR UPDATE');
            $account->execute([$subject]);
            $link = $this->db->prepare('SELECT purpose, session_version FROM pd_account_links WHERE token_hash = ? AND expires_at > ? FOR UPDATE');
            $link->execute([$hash, time()]);
            $user = $account->fetch();
            $grant = $link->fetch();
            if (!$user || !$grant || !$user['enabled']
                || (int) $user['session_version'] !== (int) $grant['session_version']
                || (bool) $user['email_verified'] !== ($grant['purpose'] === 'reset')) {
                $this->db->rollBack();
                return false;
            }
            $update = $this->db->prepare('UPDATE pd_accounts SET password_hash = ?, email_verified = TRUE, session_version = session_version + 1 WHERE subject = ?');
            $update->execute([$passwordHash, $subject]);
            $this->db->prepare('DELETE FROM pd_account_links WHERE subject = ?')->execute([$subject]);
            $this->db->commit();
            return true;
        } catch (Throwable $error) {
            $this->db->rollBack();
            throw $error;
        }
    }

    public static function mailKey(): string
    {
        $source = base64_decode(getenv('PD_OIDC_ENCRYPTION_KEY') ?: '', true);
        if ($source === false || strlen($source) !== 32) {
            throw new RuntimeException('Account mail requires a valid deployment encryption key.');
        }
        return hash_hmac('sha256', 'PD-OIDC account email links v1', $source, true);
    }
}
