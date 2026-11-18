<?php
declare(strict_types=1);

namespace PdOidc\Pilot;

use PdOidc\Distribution;
use PdOidc\Web\Theme;
use PDO;
use PHPMailer\PHPMailer\Exception as MailException;
use PHPMailer\PHPMailer\PHPMailer;
use RuntimeException;

final class AccountMail
{
    public function __construct(private readonly PDO $db) {}

    public function drain(): int
    {
        $from = getenv('PD_MAIL_FROM') ?: '';
        $host = getenv('PD_SMTP_HOST') ?: '';
        $port = (int) (getenv('PD_SMTP_PORT') ?: '465');
        $password = getenv('PD_SMTP_PASSWORD') ?: '';
        $issuer = Distribution::issuer();
        if (!filter_var($from, FILTER_VALIDATE_EMAIL) || !preg_match('/\A[A-Za-z0-9.-]+\z/', $host)
            || !in_array($port, [465, 587], true) || $password === ''
            || !str_starts_with($issuer, 'https://')) {
            throw new RuntimeException('Configure authenticated account mail and an HTTPS issuer.');
        }
        $sender = new PHPMailer(true);
        $sender->isSMTP();
        $sender->Host = $host;
        $sender->Port = $port;
        $sender->SMTPSecure = $port === 465 ? PHPMailer::ENCRYPTION_SMTPS : PHPMailer::ENCRYPTION_STARTTLS;
        $sender->SMTPAuth = true;
        $sender->Username = $from;
        $sender->Password = $password;
        $sender->Timeout = 8;
        $sender->CharSet = PHPMailer::CHARSET_UTF8;
        $brand = Theme::current()->name;
        $sender->setFrom($from, $brand);

        $now = time();
        $this->db->prepare('DELETE FROM pd_account_links WHERE expires_at <= ? ORDER BY expires_at LIMIT 1000')->execute([$now]);
        $this->db->prepare('DELETE FROM pd_public_attempts WHERE window_id < ? ORDER BY window_id LIMIT 1000')->execute([intdiv($now, 3600) - 1]);
        $read = $this->db->prepare(<<<'SQL'
            SELECT m.token_hash, m.sealed_token, m.attempts, l.purpose, a.email
            FROM pd_account_mail m JOIN pd_account_links l ON l.token_hash = m.token_hash
            JOIN pd_accounts a ON a.subject = l.subject
            WHERE m.next_attempt_at <= ? AND l.expires_at > ? AND a.enabled = TRUE
                AND a.session_version = l.session_version AND (a.email_verified = (l.purpose = 'reset'))
            ORDER BY m.next_attempt_at LIMIT 10
            SQL);
        $read->execute([$now, $now]);
        $claim = $this->db->prepare(<<<'SQL'
            UPDATE pd_account_mail SET next_attempt_at = ?, attempts = attempts + 1
            WHERE token_hash = ? AND next_attempt_at <= ?
            SQL);
        $sent = 0;
        foreach ($read->fetchAll() as $mail) {
            $hold = min(1800, 60 * (2 ** min(5, (int) $mail['attempts'])));
            $claim->execute([time() + $hold, $mail['token_hash'], time()]);
            if ($claim->rowCount() !== 1) {
                continue;
            }
            $nonceSize = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
            $sealed = $mail['sealed_token'];
            $token = sodium_crypto_secretbox_open(substr($sealed, $nonceSize), substr($sealed, 0, $nonceSize), AccountLinks::mailKey());
            if ($token === false || !hash_equals($mail['token_hash'], hash('sha256', $token))) {
                error_log('PD-OIDC could not decrypt a queued account email.');
                continue;
            }
            $activation = $mail['purpose'] === 'activate';
            $subject = $activation ? "Set up your $brand account" : "Reset your $brand password";
            $message = $activation
                ? "Your account request was approved. Set your password within 48 hours using this link.\n\n"
                : "Use this link within 45 minutes to choose a new password.\n\n";
            $message .= $issuer . '/password/reset#' . $token . "\n\nIf the link doesn’t open, use this code on the password page:\n"
                . $token . "\n\nIf you didn’t request this, you can ignore this email.";
            $sender->clearAllRecipients();
            try {
                $sender->addAddress($mail['email']);
                $sender->Subject = $subject;
                $sender->Body = $message;
                $sender->send();
                $this->db->prepare('DELETE FROM pd_account_mail WHERE token_hash = ?')->execute([$mail['token_hash']]);
                ++$sent;
            } catch (MailException) {
                error_log('PD-OIDC account email was not accepted by the configured SMTP relay.');
            }
        }
        return $sent;
    }
}
