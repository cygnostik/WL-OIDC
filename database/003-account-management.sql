CREATE TABLE IF NOT EXISTS pd_identity_admins (
    subject CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    FOREIGN KEY (subject) REFERENCES pd_accounts (subject) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS pd_signup_requests (
    id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    email VARCHAR(254) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
    first_name VARCHAR(80) NOT NULL,
    last_name VARCHAR(80) NOT NULL,
    note VARCHAR(1000) NOT NULL,
    created_at BIGINT UNSIGNED NOT NULL,
    INDEX (created_at, id)
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4;

CREATE TABLE IF NOT EXISTS pd_account_links (
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    subject CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    purpose ENUM('activate', 'reset') NOT NULL,
    session_version BIGINT UNSIGNED NOT NULL,
    expires_at BIGINT UNSIGNED NOT NULL,
    INDEX (expires_at),
    FOREIGN KEY (subject) REFERENCES pd_accounts (subject) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS pd_account_mail (
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    sealed_token VARBINARY(160) NOT NULL,
    next_attempt_at BIGINT UNSIGNED NOT NULL,
    attempts SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    INDEX (next_attempt_at),
    FOREIGN KEY (token_hash) REFERENCES pd_account_links (token_hash) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS pd_public_attempts (
    bucket CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    window_id BIGINT UNSIGNED NOT NULL,
    attempts SMALLINT UNSIGNED NOT NULL,
    INDEX (window_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS pd_identity_audit (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    actor CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    operation VARCHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    target VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at BIGINT UNSIGNED NOT NULL,
    INDEX (actor, created_at)
) ENGINE=InnoDB;
