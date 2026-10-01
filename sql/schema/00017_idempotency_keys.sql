-- Idempotency-Key (F1). A chave é reservada ANTES de qualquer execução
-- (state=in_progress) e só vira completed na mesma transação que persiste o
-- resultado. Falha sem efeito persistido apaga a linha (a chave pode ser
-- reutilizada). fingerprint nunca inclui credenciais. response_body nunca
-- contém achados (ver store_findings no contrato v1). Validade: 24h.
CREATE TABLE idempotency_keys (
    principal TEXT NOT NULL,
    idem_key TEXT NOT NULL,
    route TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('in_progress', 'completed')),
    response_status INTEGER,
    response_body JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (principal, idem_key)
);

CREATE INDEX idempotency_keys_created_at_idx ON idempotency_keys (created_at);
