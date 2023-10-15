-- Your SQL goes here
CREATE TABLE IF NOT EXISTS users
(
    user_id                  VARCHAR(36) NOT NULL,
    version                  BIGINT      NOT NULL DEFAULT 0,
    username                 VARCHAR(100) NOT NULL,
    roles                    BIGINT      NOT NULL DEFAULT 0,
    salt                     VARCHAR(32) NOT NULL,
    nonce                    VARCHAR(32) NOT NULL,
    encrypted_value          TEXT        NOT NULL,
    created_at               TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id)
);

CREATE UNIQUE INDEX users_username_ndx ON users (username);
