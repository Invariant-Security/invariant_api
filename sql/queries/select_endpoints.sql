-- Um endpoint por linha, com a classificação mais recente (se houver
-- alguma rodada de discovery já feita pra ele) e o resumo da avaliação
-- mais recente (se houver alguma rodada de assess já feita), ambos via
-- LATERAL -- evita N+1 query por endpoint na rota GET /endpoints.
SELECT
    e.id,
    e.address,
    e.label,
    e.tags,
    e.created_at,
    latest_discovery.classification,
    latest_discovery.confidence,
    latest_discovery.scanned_at,
    latest_assessment.target_type AS last_assessment_target_type,
    latest_assessment.pass_count AS last_assessment_pass_count,
    latest_assessment.fail_count AS last_assessment_fail_count,
    latest_assessment.not_assessed_count AS last_assessment_not_assessed_count,
    latest_assessment.not_applicable_count AS last_assessment_not_applicable_count,
    latest_assessment.compliance_pct AS last_assessment_compliance_pct,
    latest_assessment.assessed_at AS last_assessed_at
FROM endpoints e
LEFT JOIN LATERAL (
    SELECT classification, confidence, scanned_at
    FROM discovery_results dr
    WHERE dr.endpoint_id = e.id
    ORDER BY dr.scanned_at DESC
    LIMIT 1
) latest_discovery ON true
LEFT JOIN LATERAL (
    SELECT target_type, pass_count, fail_count, not_assessed_count, not_applicable_count, compliance_pct, assessed_at
    FROM assessment_summaries a
    WHERE a.endpoint_id = e.id
    ORDER BY a.assessed_at DESC
    LIMIT 1
) latest_assessment ON true
ORDER BY e.created_at DESC;
