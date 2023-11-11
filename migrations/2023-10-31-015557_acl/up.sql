-- Your SQL goes here

CREATE TABLE IF NOT EXISTS acls
(
    acl_id            VARCHAR(36) NOT NULL,
    version           BIGINT      NOT NULL DEFAULT 0,
    acl_user_id       VARCHAR(36) NOT NULL REFERENCES users(user_id),
    resource_type     VARCHAR(50) NOT NULL,
    resource_id       VARCHAR(36) NOT NULL,
    permissions       BIGINT      NOT NULL DEFAULT 0,
    scope             VARCHAR(50) NOT NULL,
    created_at        TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (acl_id)
);

CREATE INDEX acl_user_ndx ON acls (acl_user_id);
CREATE INDEX acl_resource_ndx ON acls (resource_type, resource_id);
CREATE UNIQUE INDEX acl_user_resource_ndx ON acls (acl_user_id, resource_type, resource_id);
