CREATE TABLE demo_host_aliases (
    endpoint_id INTEGER PRIMARY KEY REFERENCES endpoints (id) ON DELETE CASCADE,
    alias_label TEXT NOT NULL UNIQUE,
    alias_address TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
