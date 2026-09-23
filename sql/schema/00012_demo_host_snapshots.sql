CREATE TABLE demo_host_snapshots (
    id SERIAL PRIMARY KEY,
    hosts JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);
