-- Your SQL goes here
CREATE TABLE IF NOT EXISTS login_sessions
(
    login_session_id         VARCHAR(64) NOT NULL,
    user_id                  VARCHAR(36) NOT NULL REFERENCES users(user_id),
    source                   VARCHAR(64) NULL,
    ip_address               VARCHAR(64) NULL,
    created_at               TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    signed_out_at            TIMESTAMP   NULL,
    PRIMARY KEY (login_session_id)
);

CREATE INDEX login_sessions_user_ndx ON login_sessions (user_id);
