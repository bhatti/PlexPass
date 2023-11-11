-- Your SQL goes here
CREATE TABLE IF NOT EXISTS audit_records
(
    audit_id                 VARCHAR(36) NOT NULL,
    user_id                  VARCHAR(36) NOT NULL REFERENCES users(user_id),
    kind                     VARCHAR(50) NOT NULL,
    ip_address               VARCHAR(50) NULL,
    context                  VARCHAR(200) NOT NULL,
    message                  VARCHAR(200) NOT NULL,
    created_at               TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (audit_id)
);

CREATE INDEX audit_records_user_ndx ON audit_records (user_id);
CREATE INDEX audit_records_kind_ndx ON audit_records (kind);
