-- Snapshot da demo pública -- append-only (histórico completo fica, sem
-- upsert, mesmo padrão de discovery_results), sempre já sanitizado pelo
-- backend antes de chegar aqui (routes/demo_snapshot.py: alias fictício
-- + leak scan contra identificadores reais conhecidos -- nunca confia
-- em payload "já anonimizado" pelo frontend). GET público só considera
-- WHERE revoked_at IS NULL ORDER BY id DESC LIMIT 1 -- despublicar é só
-- marcar revoked_at, sem precisar de SQL manual nem apagar o histórico.
CREATE TABLE demo_snapshots (
    id SERIAL PRIMARY KEY,
    containers JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);
