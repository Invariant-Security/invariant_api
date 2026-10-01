-- Eventos de domínio locais (F1), gravados na MESMA transação do fato que
-- descrevem (hoje: assessment.completed). Não é o webhook: a entrega para
-- fora (F4) vai ler daqui. event_id é imutável e vira o id do evento
-- entregue, para quem recebe poder deduplicar.
CREATE TABLE domain_events (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
