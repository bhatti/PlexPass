-- Your SQL goes here
CREATE TABLE IF NOT EXISTS settings
(
    setting_id        VARCHAR(36) NOT NULL,
    version           BIGINT      NOT NULL DEFAULT 0,
    user_id           VARCHAR(36) NOT NULL REFERENCES users(user_id),
    kind              VARCHAR(50) NOT NULL,
    name              VARCHAR(50) NOT NULL,
    value             VARCHAR(200) NOT NULL,
    created_at        TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (setting_id)
);

CREATE INDEX settings_kind_ndx ON settings (kind);
CREATE UNIQUE INDEX setting_name_ndx ON lookups (user_id, kind, name);
