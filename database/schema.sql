-- PhishGuard database schema (for phpMyAdmin > Import, or the SQL tab).
-- The Java app also creates this automatically on first start.

CREATE DATABASE IF NOT EXISTS phishguard
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE phishguard;

CREATE TABLE IF NOT EXISTS scans (
  id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  scan_id           VARCHAR(20)  NOT NULL UNIQUE,
  url               VARCHAR(2048) NOT NULL,
  risk_score        TINYINT UNSIGNED NOT NULL,
  risk_level        VARCHAR(12)  NOT NULL,
  attack_type       VARCHAR(40),
  risk_factor_count SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  execution_ms      INT UNSIGNED NOT NULL DEFAULT 0,
  technical_details MEDIUMTEXT,
  scanned_at        VARCHAR(19)  NOT NULL,
  created_at        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_created (created_at),
  INDEX idx_level (risk_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Handy queries to show in phpMyAdmin:
-- SELECT scan_id, url, risk_score, risk_level, attack_type, scanned_at FROM scans ORDER BY id DESC;
-- SELECT risk_level, COUNT(*) AS total, ROUND(AVG(risk_score),1) AS avg_score FROM scans GROUP BY risk_level;

-- Login accounts (created automatically by the app; passwords are stored as salted PBKDF2 hashes)
CREATE TABLE IF NOT EXISTS users (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(30)  NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
