-- Identidade pública e contexto de cada avaliação (F1). public_id é o
-- assessment_id do contrato v1 (UUID, nunca o SERIAL interno). assessed_ip
-- é o IP que de fato foi avaliado (um CIDR avalia um host por vez); linhas
-- anteriores a esta migration ficam com NULL. source distingue console e
-- API (a API por chave chega na F4).
ALTER TABLE assessment_summaries
    ADD COLUMN public_id UUID NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN assessed_ip TEXT,
    ADD COLUMN source TEXT NOT NULL DEFAULT 'console' CHECK (source IN ('console', 'api'));

CREATE UNIQUE INDEX assessment_summaries_public_id_idx ON assessment_summaries (public_id);

-- Avaliações anteriores: quando o endpoint é um IP único, o host avaliado
-- só pode ter sido ele. Endpoint CIDR: não há como saber qual IP foi
-- avaliado -- fica NULL (e essas linhas não aparecem na listagem v1, que
-- exige assessed_ip), em vez de inventar um valor.
UPDATE assessment_summaries s
SET assessed_ip = host(e.address::inet)
FROM endpoints e
WHERE s.endpoint_id = e.id
  AND s.assessed_ip IS NULL
  AND masklen(e.address::inet) = CASE WHEN family(e.address::inet) = 4 THEN 32 ELSE 128 END;
