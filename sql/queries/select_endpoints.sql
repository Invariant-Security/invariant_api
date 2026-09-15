-- Um endpoint por linha, com a classificação mais recente (se houver
-- alguma rodada de discovery já feita pra ele) via LATERAL -- evita N+1
-- query por endpoint na rota GET /endpoints.
SELECT
    e.id,
    e.address,
    e.label,
    e.tags,
    e.created_at,
    latest.classification,
    latest.confidence,
    latest.scanned_at
FROM endpoints e
LEFT JOIN LATERAL (
    SELECT classification, confidence, scanned_at
    FROM discovery_results dr
    WHERE dr.endpoint_id = e.id
    ORDER BY dr.scanned_at DESC
    LIMIT 1
) latest ON true
ORDER BY e.created_at DESC;
