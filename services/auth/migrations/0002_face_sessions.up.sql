-- auth-service | 0002 | face signup, device sessions, login attempts, rate limits

-- signup: opaque face reference (shared with face-service) + biometric consent record
ALTER TABLE signup_sessions
    ADD COLUMN face_ref        uuid NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN consented_at    timestamptz,
    ADD COLUMN consent_version text,
    ADD COLUMN user_id         uuid REFERENCES users(id);

-- the user's face reference never changes; the face template lives only in face-service
ALTER TABLE users ADD COLUMN face_ref uuid NOT NULL UNIQUE;

-- one row per logged-in device. Refresh tokens rotate; the previous hash is kept to detect reuse.
CREATE TABLE sessions (
    id                   uuid        PRIMARY KEY,
    user_id              uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    current_refresh_hash bytea       NOT NULL,
    prev_refresh_hash    bytea,
    client_ip            inet,
    user_agent           text,
    created_at           timestamptz NOT NULL DEFAULT now(),
    last_used_at         timestamptz NOT NULL DEFAULT now(),
    expires_at           timestamptz NOT NULL,
    revoked_at           timestamptz
);
CREATE INDEX sessions_user_active_idx ON sessions (user_id) WHERE revoked_at IS NULL;

-- short-lived: "this client asked to log in as this user and holds this face challenge"
CREATE TABLE login_attempts (
    token_hash        bytea       PRIMARY KEY,
    user_id           uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    face_challenge_id text        NOT NULL,
    expires_at        timestamptz NOT NULL
);
CREATE INDEX login_attempts_expires_idx ON login_attempts (expires_at);

-- fixed-window counters (shared across replicas). A janitor deletes old windows.
CREATE TABLE rate_limits (
    key          text        NOT NULL,
    window_start timestamptz NOT NULL,
    hits         int         NOT NULL DEFAULT 0,
    PRIMARY KEY (key, window_start)
);
