CREATE TABLE IF NOT EXISTS pd_oidc_login_policies (
    client_id VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    days SMALLINT UNSIGNED NOT NULL,
    generation BIGINT UNSIGNED NOT NULL DEFAULT 0,
    FOREIGN KEY (client_id) REFERENCES pd_oidc_clients (client_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS pd_oidc_refresh_sessions (
    id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    client_id VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    subject CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    session_version BIGINT UNSIGNED NOT NULL,
    policy_generation BIGINT UNSIGNED NOT NULL,
    auth_time BIGINT UNSIGNED NOT NULL,
    scopes VARCHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_at BIGINT UNSIGNED NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    INDEX (expires_at),
    FOREIGN KEY (client_id) REFERENCES pd_oidc_clients (client_id) ON DELETE CASCADE,
    FOREIGN KEY (subject) REFERENCES pd_accounts (subject) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS pd_oidc_refresh_tokens (
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    session_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    spent BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (session_id) REFERENCES pd_oidc_refresh_sessions (id) ON DELETE CASCADE
) ENGINE=InnoDB;
