-- Your SQL goes here

CREATE TABLE IF NOT EXISTS lookups
(
    lookup_id         VARCHAR(36) NOT NULL,
    version           BIGINT      NOT NULL DEFAULT 0,
    user_id           VARCHAR(36) NOT NULL REFERENCES users(user_id),
    kind              VARCHAR(50) NOT NULL,
    name              VARCHAR(200) NOT NULL,
    created_at        TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (lookup_id)
);

CREATE INDEX lookups_kind_ndx ON lookups (kind);
CREATE UNIQUE INDEX lookups_name_ndx ON lookups (user_id, kind, name);
