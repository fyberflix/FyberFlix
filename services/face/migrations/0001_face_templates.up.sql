-- face-service | 0001 | encrypted face templates (own database, never shared with auth)
BEGIN;
CREATE TABLE face_templates (
    subject_ref uuid        PRIMARY KEY,           -- opaque id issued by auth-service
    key_id      text        NOT NULL,              -- which key encrypted this row
    nonce       bytea       NOT NULL,
    ciphertext  bytea       NOT NULL,              -- AES-256-GCM(float32 template), AAD = subject_ref|model_id
    model_id    text        NOT NULL,              -- templates from different models are not comparable
    created_at  timestamptz NOT NULL DEFAULT now()
);
COMMIT;
