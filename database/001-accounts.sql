CREATE TABLE IF NOT EXISTS pd_accounts (
    subject CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    email VARCHAR(254) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
    display_name VARCHAR(160) NOT NULL,
    password_hash VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    session_version INT UNSIGNED NOT NULL DEFAULT 0,
    allow_all_services BOOLEAN NOT NULL DEFAULT TRUE,
    default_role ENUM('read', 'write', 'admin') NOT NULL DEFAULT 'read'
) ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4;

CREATE TABLE IF NOT EXISTS pd_services (
    client_id VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    requires_operator BOOLEAN NOT NULL DEFAULT FALSE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS pd_service_overrides (
    subject CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    client_id VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    access_override BOOLEAN NULL,
    role_override ENUM('read', 'write', 'admin') NULL,
    PRIMARY KEY (subject, client_id),
    FOREIGN KEY (subject) REFERENCES pd_accounts (subject) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES pd_services (client_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS pd_login_attempts (
    bucket CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    window_id BIGINT UNSIGNED NOT NULL,
    attempts SMALLINT UNSIGNED NOT NULL,
    INDEX (window_id)
) ENGINE=InnoDB;
