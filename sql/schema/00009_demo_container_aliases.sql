-- Vínculo privado container_id (Docker ID real, completo, não truncado)
-- -> identidade fictícia publicada na demo. NUNCA exposto em nenhuma
-- resposta pública -- só o backend consulta isso, pra manter o mesmo
-- alias estável entre publicações (rename/restart do mesmo container
-- mantém o mesmo Docker ID; recriar o container gera um ID novo e pode
-- receber um alias novo -- limitação aceita nesta rodada).
CREATE TABLE demo_container_aliases (
    container_id TEXT PRIMARY KEY,
    alias_name TEXT NOT NULL UNIQUE,
    alias_image TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
