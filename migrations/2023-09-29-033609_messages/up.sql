-- Your SQL goes here
CREATE TABLE IF NOT EXISTS messages
(
    message_id        VARCHAR(36) NOT NULL,
    user_id           VARCHAR(36) NOT NULL REFERENCES users(user_id),
    specversion       VARCHAR(16) NOT NULL,
    source            VARCHAR(50) NOT NULL,
    kind              VARCHAR(50) NOT NULL,
    flags             BIGINT      NOT NULL DEFAULT 0,
    salt              VARCHAR(32) NOT NULL,
    nonce             VARCHAR(32) NOT NULL,
    encrypted_value   TEXT        NOT NULL,
    created_at        TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (message_id)
);

CREATE INDEX messages_kind_ndx ON messages (kind);
