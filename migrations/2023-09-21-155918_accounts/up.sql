-- Your SQL goes here
CREATE TABLE IF NOT EXISTS accounts
(
    account_id        VARCHAR(36) NOT NULL,
    version           BIGINT      NOT NULL DEFAULT 0,
    vault_id          VARCHAR(36) NOT NULL REFERENCES vaults(vault_id),
    archived_version  BIGINT,
    salt              VARCHAR(32) NOT NULL,
    nonce             VARCHAR(32) NOT NULL,
    encrypted_value   TEXT        NOT NULL,
    value_hash        VARCHAR(64) NOT NULL,
    credentials_updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at        TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (account_id)
);

CREATE INDEX accounts_vault_id_ndx ON accounts (vault_id);
CREATE UNIQUE INDEX accounts_vault_id_hash_ndx ON accounts (vault_id, value_hash);

CREATE TABLE IF NOT EXISTS archived_accounts
(
    account_id        VARCHAR(36) NOT NULL,
    version           BIGINT      NOT NULL DEFAULT 0,
    vault_id          VARCHAR(36) NOT NULL REFERENCES vaults(vault_id),
    crypto_key_id     VARCHAR(36) NOT NULL,
    salt              VARCHAR(32) NOT NULL,
    nonce             VARCHAR(32) NOT NULL,
    encrypted_value   TEXT        NOT NULL,
    value_hash        VARCHAR(64) NOT NULL,
    created_at        TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (account_id, version)
);

CREATE INDEX archived_accounts_vault_id_ndx ON archived_accounts (vault_id);

