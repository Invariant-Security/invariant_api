SELECT target_type, pass_count, fail_count, not_assessed_count, not_applicable_count, compliance_pct, assessed_at
FROM assessment_summaries
WHERE endpoint_id = %(endpoint_id)s
ORDER BY assessed_at DESC
LIMIT 1;
