CREATE TABLE IF NOT EXISTS pd_oidc_clients (
    client_id VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    display_name VARCHAR(160) NOT NULL,
    callbacks_json TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES pd_services (client_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4;

CREATE TABLE IF NOT EXISTS pd_oidc_access_token_clients (
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    client_id VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    FOREIGN KEY (token_hash) REFERENCES pd_oidc_access_tokens (token_hash) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES pd_oidc_clients (client_id) ON DELETE CASCADE
) ENGINE=InnoDB;
