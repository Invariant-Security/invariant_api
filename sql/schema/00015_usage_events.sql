-- Consumo (F1). Um evento bruto por avaliação CONCLUÍDA e persistida --
-- append-only. A cobrança NÃO conta eventos: conta identidades distintas
-- (host_kind, host_key) por período UTC (ver count_billable_hosts.sql), então
-- avaliar o mesmo host 20 vezes no mês continua sendo 1 unidade.
--
-- Sem FK de propósito: apagar um endpoint (ou o resumo, que cai em cascata
-- com ele) não pode apagar consumo já realizado.
CREATE TABLE usage_events (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    host_kind TEXT NOT NULL CHECK (host_kind IN ('linux_host', 'docker_container')),
    -- já normalizado (invariant_contracts.usage.normalize_host_ip)
    host_key TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('console', 'api')),
    endpoint_id INTEGER,
    assessment_public_id UUID
);

CREATE INDEX usage_events_occurred_at_idx ON usage_events (occurred_at);
