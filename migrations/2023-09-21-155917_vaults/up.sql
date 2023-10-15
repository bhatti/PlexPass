-- Your SQL goes here
CREATE TABLE IF NOT EXISTS vaults
(
    vault_id          VARCHAR(36) NOT NULL,
    version           BIGINT      NOT NULL DEFAULT 0,
    owner_user_id     VARCHAR(36) NOT NULL REFERENCES users(user_id),
    title             VARCHAR(50) NOT NULL,
    salt              VARCHAR(32) NOT NULL,
    nonce             VARCHAR(32) NOT NULL,
    encrypted_value   TEXT        NOT NULL,
    created_at        TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vault_id)
);

CREATE INDEX vaults_user_ndx ON vaults (owner_user_id);
CREATE UNIQUE INDEX vaults_title_ndx ON vaults (owner_user_id, title);

CREATE TABLE IF NOT EXISTS users_vaults
(
    user_vault_id     VARCHAR(36) NOT NULL,
    user_id           VARCHAR(36) NOT NULL REFERENCES users(user_id),
    vault_id          VARCHAR(36) NOT NULL REFERENCES vaults(vault_id),
    created_at        TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_vault_id)
);

CREATE UNIQUE INDEX users_vault_ndx ON users_vaults (user_id, vault_id);
