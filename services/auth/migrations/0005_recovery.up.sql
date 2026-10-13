-- auth-service | 0005 | account recovery when the face no longer matches (injury, new camera, ...)
--
-- Flow: email OTP (verified email only) -> 'waiting' request (7-day delay, owner is notified and can
-- cancel by simply logging in) -> admin approval -> face re-enrolment -> 'completed'.

CREATE TABLE recovery_otps (
    user_id    uuid        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    code_hash  bytea       NOT NULL,
    attempts   int         NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL
);

CREATE TABLE recovery_requests (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   bytea       NOT NULL UNIQUE,
    state        text        NOT NULL DEFAULT 'waiting'
                 CHECK (state IN ('waiting','approved','completed','cancelled','expired')),
    ready_at     timestamptz NOT NULL,           -- not usable before this moment, even if approved
    approved_by  uuid,
    approved_at  timestamptz,
    completed_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);
-- at most one open request per account
CREATE UNIQUE INDEX recovery_one_open ON recovery_requests (user_id) WHERE state IN ('waiting','approved');

ALTER TABLE face_attempts DROP CONSTRAINT IF EXISTS face_attempts_purpose_check;
ALTER TABLE face_attempts ADD CONSTRAINT face_attempts_purpose_check
    CHECK (purpose IN ('delete','restore','recover'));
