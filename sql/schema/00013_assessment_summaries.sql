-- Resumo leve de uma rodada de avaliação SSH real (POST
-- /endpoints/{id}/assess) -- nunca as Findings em si (evidence_output,
-- achado por achado, comandos, remediação, credenciais). Contagens
-- usam exatamente a mesma taxonomia de invariant_api.reports.
-- split_findings()/compliance_pct() já usada nos relatórios PDF, não
-- uma regra nova reinventada aqui. Histórico completo (sem upsert),
-- mesmo padrão de discovery_results -- GET /endpoints só expõe a
-- linha mais recente por endpoint via LEFT JOIN LATERAL.
CREATE TABLE assessment_summaries (
    id SERIAL PRIMARY KEY,
    endpoint_id INTEGER NOT NULL REFERENCES endpoints (id) ON DELETE CASCADE,
    target_type TEXT NOT NULL,
    pass_count INTEGER NOT NULL,
    fail_count INTEGER NOT NULL,
    not_assessed_count INTEGER NOT NULL,
    not_applicable_count INTEGER NOT NULL,
    compliance_pct INTEGER,
    assessed_at TIMESTAMPTZ NOT NULL
);

-- Composto, não só (endpoint_id): toda leitura real é "a mais recente
-- DESTE endpoint", nunca "todas de um endpoint" sem ordenação -- o
-- índice já cobre a ordenação que o LATERAL faz.
CREATE INDEX assessment_summaries_endpoint_assessed_idx
    ON assessment_summaries (endpoint_id, assessed_at DESC);
