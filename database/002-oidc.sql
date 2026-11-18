CREATE TABLE IF NOT EXISTS pd_oidc_codes (
    id CHAR(80) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    subject CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    session_version BIGINT UNSIGNED NOT NULL,
    nonce VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL,
    auth_time BIGINT UNSIGNED NOT NULL,
    expires_at BIGINT UNSIGNED NOT NULL,
    consumed BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id),
    KEY pd_oidc_codes_expires_at (expires_at),
    CONSTRAINT pd_oidc_codes_subject FOREIGN KEY (subject) REFERENCES pd_accounts (subject) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS pd_oidc_access_tokens (
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    subject CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    session_version BIGINT UNSIGNED NOT NULL,
    profile_scope BOOLEAN NOT NULL,
    email_scope BOOLEAN NOT NULL,
    expires_at BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (token_hash),
    KEY pd_oidc_access_tokens_expires_at (expires_at),
    CONSTRAINT pd_oidc_access_tokens_subject FOREIGN KEY (subject) REFERENCES pd_accounts (subject) ON DELETE CASCADE
) ENGINE=InnoDB;
