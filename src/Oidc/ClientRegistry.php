<?php
declare(strict_types=1);

namespace PdOidc\Oidc;

use PDO;
use Throwable;

final class ClientRegistry
{
    public function __construct(private readonly PDO $db) {}

    public function find(string $id): ?RegisteredClient
    {
        $query = <<<'SQL'
            SELECT c.client_id, c.display_name, c.callbacks_json
            FROM pd_oidc_clients c JOIN pd_services s USING (client_id)
            WHERE c.client_id = ? AND s.enabled = TRUE
            SQL;
        $query = $this->db->prepare($query . ($this->db->inTransaction() ? ' LOCK IN SHARE MODE' : ''));
        $query->execute([$id]);
        $row = $query->fetch();
        return $row ? new RegisteredClient($row['client_id'], $row['display_name'],
            json_decode($row['callbacks_json'], true, flags: JSON_THROW_ON_ERROR)) : null;
    }

    public function save(RegisteredClient $client, bool $operatorOnly, bool $legacyBootstrap = false): void
    {
        $id = $client->getIdentifier();
        $this->db->beginTransaction();
        try {
            $policy = 'INSERT INTO pd_services (client_id, requires_operator) VALUES (?, ?)';
            $policy .= $legacyBootstrap ? ' ON DUPLICATE KEY UPDATE client_id = pd_services.client_id'
                : ' ON DUPLICATE KEY UPDATE requires_operator = ?';
            $this->db->prepare($policy)->execute(
                $legacyBootstrap ? [$id, (int) $operatorOnly] : [$id, (int) $operatorOnly, (int) $operatorOnly],
            );
            $config = 'INSERT INTO pd_oidc_clients (client_id, display_name, callbacks_json) VALUES (?, ?, ?)';
            $config .= $legacyBootstrap ? ' ON DUPLICATE KEY UPDATE client_id = pd_oidc_clients.client_id'
                : ' ON DUPLICATE KEY UPDATE display_name = ?, callbacks_json = ?';
            $name = $client->getName();
            $callbacks = json_encode($client->getRedirectUri(), JSON_THROW_ON_ERROR);
            $this->db->prepare($config)->execute($legacyBootstrap ? [$id, $name, $callbacks] : [$id, $name, $callbacks, $name, $callbacks]);
            if ($legacyBootstrap) {
                // Before client bindings were stored, all access tokens belonged to this one client.
                $this->db->prepare(<<<'SQL'
                    INSERT INTO pd_oidc_access_token_clients (token_hash, client_id)
                    SELECT t.token_hash, ? FROM pd_oidc_access_tokens t
                    LEFT JOIN pd_oidc_access_token_clients c USING (token_hash)
                    WHERE c.token_hash IS NULL AND t.expires_at > ?
                    SQL)->execute([$id, time()]);
            }
            $this->db->commit();
        } catch (Throwable $error) {
            if ($this->db->inTransaction()) {
                $this->db->rollBack();
            }
            throw $error;
        }
    }
}
