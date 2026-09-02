-- Um resultado de classificação por IP -- um endpoint que é um /24 gera
-- até 254 linhas aqui por rodada de discovery, um endpoint IP único gera
-- 1. Histórico completo fica (sem upsert): `select_latest_discovery_results_by_endpoint`
-- pega só a rodada mais recente por IP.
CREATE TABLE discovery_results (
    id SERIAL PRIMARY KEY,
    endpoint_id INTEGER NOT NULL REFERENCES endpoints (id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    classification TEXT NOT NULL,
    confidence REAL NOT NULL,
    evidence JSONB NOT NULL,
    scanned_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX discovery_results_endpoint_id_idx ON discovery_results (endpoint_id);
