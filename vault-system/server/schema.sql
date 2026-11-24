-- Schema CSDL của Vault server. Chạy tự động khi server khởi động (CREATE ... IF NOT EXISTS).
-- CSDL không bao giờ chứa mật khẩu két, PIN hay PUK dạng rõ.

CREATE TABLE IF NOT EXISTS admins (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(64)  NOT NULL UNIQUE,
    password_hash VARCHAR(100) NOT NULL,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cards (
    card_id          CHAR(8)      NOT NULL PRIMARY KEY,
    owner_name       VARCHAR(64)  NOT NULL,
    owner_email      VARCHAR(64)  NULL,
    owner_phone      VARCHAR(16)  NULL,
    rsa_modulus      VARBINARY(256) NOT NULL,
    rsa_exponent     VARBINARY(8)   NOT NULL,
    -- Trạng thái quản trị (nguồn sự thật để chấp nhận / từ chối thẻ)
    status           ENUM('PENDING','ACTIVE','LOCKED','REVOKED') NOT NULL DEFAULT 'PENDING',
    -- Trạng thái thực tế trên thẻ, theo lần báo cáo gần nhất
    card_state       ENUM('UNKNOWN','ACTIVE','PIN_BLOCKED','ADMIN_LOCKED','REVOKED','DISABLED') NOT NULL DEFAULT 'UNKNOWN',
    -- Thao tác admin chưa ghi được lên thẻ (thẻ không cắm lúc thao tác), sẽ đồng bộ khi thẻ kết nối
    pending_action   ENUM('NONE','LOCK','UNLOCK','REVOKE') NOT NULL DEFAULT 'NONE',
    replaces_card_id CHAR(8)      NULL,
    issued_by        VARCHAR(64)  NULL,
    issued_at        DATETIME     NULL,
    revoked_at       DATETIME     NULL,
    last_seen_at     DATETIME     NULL,
    created_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_cards_status (status),
    INDEX idx_cards_owner (owner_name)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    card_id    CHAR(8)      NULL,
    actor      VARCHAR(80)  NOT NULL,
    action     VARCHAR(32)  NOT NULL,
    result     ENUM('OK','FAIL') NOT NULL,
    detail     VARCHAR(255) NULL,
    ip         VARCHAR(45)  NULL,
    created_at DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    INDEX idx_logs_card (card_id, created_at),
    INDEX idx_logs_created (created_at),
    INDEX idx_logs_action (action, created_at)
);

CREATE TABLE IF NOT EXISTS backups (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    card_id    CHAR(8)    NOT NULL,
    entries    INT        NOT NULL,
    size       INT        NOT NULL,
    data       MEDIUMBLOB NOT NULL,
    created_at DATETIME   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_backups_card (card_id, created_at)
);
