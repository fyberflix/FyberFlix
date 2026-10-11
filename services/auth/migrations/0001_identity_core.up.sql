-- FyberFlix | auth-service | 0001 identity core
-- Company: ZEAIPC - Zikr-e-Ameen Innovations & Programming Corporation
BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Single source of truth for every FyberFlix Number ever issued.
-- 'held'    = shown to a signup session, temporarily reserved
-- 'assigned'= belongs to a user
-- 'retired' = account deleted; number is NEVER reissued (support/audit safety)
CREATE TABLE number_registry (
    number      char(9)     PRIMARY KEY CHECK (number ~ '^[1-9][0-9]{8}$'),
    state       text        NOT NULL CHECK (state IN ('held','assigned','retired')),
    held_by     bytea,                      -- signup session token hash
    held_until  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CHECK ((state = 'held') = (held_by IS NOT NULL AND held_until IS NOT NULL))
);
CREATE INDEX number_registry_held_by_idx ON number_registry (held_by) WHERE state = 'held';

CREATE TABLE users (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    fyberflix_number  char(9) NOT NULL UNIQUE REFERENCES number_registry(number),
    fyber_cable_name  text    NOT NULL CHECK (char_length(fyber_cable_name) BETWEEN 3 AND 30),
    fyber_cable_key   text    NOT NULL UNIQUE,   -- lowercase form, uniqueness is enforced here
    status            text    NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending','active','suspended','deletion_pending','deleted')),
    email             text,
    email_verified_at timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    deleted_at        timestamptz
);

-- The customer number is permanent: it can never be changed once assigned.
CREATE FUNCTION forbid_number_change() RETURNS trigger AS $$
BEGIN
    IF NEW.fyberflix_number IS DISTINCT FROM OLD.fyberflix_number THEN
        RAISE EXCEPTION 'fyberflix_number is immutable';
    END IF;
    NEW.updated_at = now();
    RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER users_number_immutable BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION forbid_number_change();

-- Signup is a state machine; each later step (face, email) advances it.
CREATE TABLE signup_sessions (
    token_hash       bytea       PRIMARY KEY,           -- sha256(token); token itself never stored
    state            text        NOT NULL DEFAULT 'started'
                     CHECK (state IN ('started','number_selected','name_chosen','face_checked','account_created','face_reverified','completed','expired')),
    selected_number  char(9),
    fyber_cable_name text,
    refresh_count    int         NOT NULL DEFAULT 0,
    client_ip        inet,
    user_agent       text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL
);
CREATE INDEX signup_sessions_expires_idx ON signup_sessions (expires_at);

COMMIT;
