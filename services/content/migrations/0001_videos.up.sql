CREATE TABLE videos (
    id               uuid PRIMARY KEY,
    owner_id         uuid        NOT NULL,
    kind             text        NOT NULL CHECK (kind IN ('reel','video')),
    status           text        NOT NULL CHECK (status IN ('awaiting_upload','processing','ready','failed','removed')),
    caption          text        NOT NULL DEFAULT '' CHECK (char_length(caption) <= 2200),
    visibility       text        NOT NULL CHECK (visibility IN ('public','unlisted','private')),
    src_key          text        NOT NULL,
    src_content_type text        NOT NULL,
    src_bytes        bigint      NOT NULL CHECK (src_bytes > 0),
    duration_ms      integer     NOT NULL DEFAULT 0,
    width            integer     NOT NULL DEFAULT 0,
    height           integer     NOT NULL DEFAULT 0,
    hls_key          text        NOT NULL DEFAULT '',
    thumb_key        text        NOT NULL DEFAULT '',
    media_keys       text[]      NOT NULL DEFAULT '{}',
    fail_reason      text        NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    published_at     timestamptz
);

-- profile pages: newest ready videos of one owner (keyset pagination)
CREATE INDEX videos_owner_published_idx ON videos (owner_id, published_at DESC, id DESC) WHERE status = 'ready';
-- "my videos" (any status except removed) and upload rate limits
CREATE INDEX videos_owner_created_idx ON videos (owner_id, created_at DESC) WHERE status <> 'removed';
-- janitor: abandoned uploads
CREATE INDEX videos_awaiting_idx ON videos (created_at) WHERE status = 'awaiting_upload';

CREATE TABLE jobs (
    id           bigserial PRIMARY KEY,
    kind         text        NOT NULL CHECK (kind IN ('transcode','purge')),
    video_id     uuid        NOT NULL REFERENCES videos(id),
    state        text        NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','done','failed')),
    attempts     integer     NOT NULL DEFAULT 0,
    max_attempts integer     NOT NULL DEFAULT 5,
    run_after    timestamptz NOT NULL DEFAULT now(),
    locked_by    text,
    locked_until timestamptz,
    last_error   text        NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- at most one active job per (video, kind): makes "enqueue" idempotent
CREATE UNIQUE INDEX jobs_active_uniq ON jobs (video_id, kind) WHERE state IN ('queued','running');
CREATE INDEX jobs_claim_idx ON jobs (run_after, id) WHERE state = 'queued';
CREATE INDEX jobs_running_idx ON jobs (locked_until) WHERE state = 'running';
