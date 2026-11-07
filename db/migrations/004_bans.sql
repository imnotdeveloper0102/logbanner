CREATE TABLE bans (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip         INET NOT NULL,
    reason     TEXT NOT NULL,
    rule_id    UUID REFERENCES rules (id) ON DELETE SET NULL,
    banned_by  UUID REFERENCES users (id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX bans_ip_idx ON bans (ip);
CREATE INDEX bans_active_idx ON bans (expires_at) WHERE revoked_at IS NULL;
