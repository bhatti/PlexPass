-- Your SQL goes here
CREATE TABLE IF NOT EXISTS crypto_keys
(
    crypto_key_id            VARCHAR(36) NOT NULL,
    parent_crypto_key_id     VARCHAR(36) NOT NULL,
    user_id                  VARCHAR(36) NOT NULL REFERENCES users(user_id),
    keyable_id               VARCHAR(36) NOT NULL,
    keyable_type             VARCHAR(50) NOT NULL,
    salt                     VARCHAR(32) NOT NULL,
    nonce                    VARCHAR(32) NOT NULL,
    public_key               VARCHAR(100) NOT NULL,
    encrypted_private_key    VARCHAR(100) NOT NULL,
    encrypted_symmetric_key  VARCHAR(100) NOT NULL,
    created_at               TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (crypto_key_id)
);

CREATE INDEX crypto_keys_user_ndx ON crypto_keys (user_id);
CREATE INDEX crypto_keys_parent_ndx ON crypto_keys (parent_crypto_key_id);
CREATE UNIQUE INDEX crypto_keys_user_keyable_ndx ON crypto_keys (user_id, keyable_id, keyable_type);
