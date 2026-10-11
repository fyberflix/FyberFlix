DROP TABLE IF EXISTS rate_limits;
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS sessions;
ALTER TABLE users DROP COLUMN IF EXISTS face_ref;
ALTER TABLE signup_sessions
    DROP COLUMN IF EXISTS user_id,
    DROP COLUMN IF EXISTS consent_version,
    DROP COLUMN IF EXISTS consented_at,
    DROP COLUMN IF EXISTS face_ref;
