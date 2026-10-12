-- auth-service | 0003 | email OTP, account management/deletion, staff roles, audit log

ALTER TABLE users
    ADD COLUMN deletion_scheduled_at timestamptz,   -- set while status = 'deletion_pending'
    ADD COLUMN cable_name_changed_at timestamptz;

-- a verified email belongs to exactly one account (unverified emails are not unique)
CREATE UNIQUE INDEX users_email_verified_uq ON users (lower(email)) WHERE email_verified_at IS NOT NULL;

-- one pending email-verification code per user; only an HMAC of the code is stored
CREATE TABLE email_otps (
    user_id    uuid        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    email      text        NOT NULL,
    code_hash  bytea       NOT NULL,
    attempts   int         NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- face step-up for destructive/recovery actions (delete account, restore account)
CREATE TABLE face_attempts (
    token_hash        bytea       PRIMARY KEY,
    user_id           uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    face_challenge_id text        NOT NULL,
    purpose           text        NOT NULL CHECK (purpose IN ('delete','restore')),
    expires_at        timestamptz NOT NULL
);
CREATE INDEX face_attempts_expires_idx ON face_attempts (expires_at);

-- released Fyber Cable names stay reserved for 90 days so nobody can take over an old URL
CREATE TABLE cable_name_history (
    key         text        PRIMARY KEY,
    user_id     uuid        NOT NULL,
    released_at timestamptz NOT NULL DEFAULT now()
);

CREATE FUNCTION forbid_recent_cable_name() RETURNS trigger AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM cable_name_history h
                WHERE h.key = NEW.fyber_cable_key AND h.user_id <> NEW.id
                  AND h.released_at > now() - interval '90 days') THEN
        RAISE EXCEPTION 'cable name was released recently'
            USING ERRCODE = '23505', CONSTRAINT = 'users_fyber_cable_key_recent';
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER users_recent_cable_name BEFORE INSERT OR UPDATE OF fyber_cable_key ON users
    FOR EACH ROW EXECUTE FUNCTION forbid_recent_cable_name();

-- staff are normal users with a role. Roles are granted in the database by an operator.
CREATE TABLE staff_roles (
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       text        NOT NULL CHECK (role IN ('support','admin')),
    granted_by text        NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role)
);

-- append-only record of security-relevant events. Never put raw PII in `detail`.
CREATE TABLE audit_log (
    id          bigserial   PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    actor_type  text        NOT NULL CHECK (actor_type IN ('user','staff','system')),
    actor_id    text        NOT NULL DEFAULT '',
    action      text        NOT NULL,
    target_user uuid,
    ip          inet,
    detail      jsonb       NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_target_idx ON audit_log (target_user, at DESC);

CREATE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'audit_log is append-only'; END $$ LANGUAGE plpgsql;
CREATE TRIGGER audit_log_no_change BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
