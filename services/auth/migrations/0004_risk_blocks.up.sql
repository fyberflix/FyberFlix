-- auth-service | 0004 | temporary blocks created by risk verdicts (e.g. repeated failed face logins)
CREATE TABLE risk_blocks (
    key        text        PRIMARY KEY,          -- 'ip:<addr>' or 'user:<uuid>'
    until      timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX risk_blocks_until_idx ON risk_blocks (until);
