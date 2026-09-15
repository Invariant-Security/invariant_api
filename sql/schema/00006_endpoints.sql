-- Um IP individual ou range/CIDR que o admin cadastrou pra descoberta.
-- `address` guarda exatamente o que foi digitado (IP único ou CIDR) --
-- a expansão de um CIDR em IPs individuais acontece em invariant_discovery,
-- não aqui.
CREATE TABLE endpoints (
    id SERIAL PRIMARY KEY,
    address TEXT NOT NULL UNIQUE,
    label TEXT,
    tags TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
