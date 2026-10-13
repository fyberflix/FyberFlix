DELETE FROM face_attempts WHERE purpose = 'recover';
ALTER TABLE face_attempts DROP CONSTRAINT IF EXISTS face_attempts_purpose_check;
ALTER TABLE face_attempts ADD CONSTRAINT face_attempts_purpose_check CHECK (purpose IN ('delete','restore'));
DROP TABLE IF EXISTS recovery_requests;
DROP TABLE IF EXISTS recovery_otps;
