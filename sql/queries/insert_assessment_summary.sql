INSERT INTO assessment_summaries
    (endpoint_id, target_type, pass_count, fail_count, not_assessed_count, not_applicable_count, compliance_pct, assessed_at)
VALUES
    (%(endpoint_id)s, %(target_type)s, %(pass_count)s, %(fail_count)s, %(not_assessed_count)s, %(not_applicable_count)s, %(compliance_pct)s, %(assessed_at)s)
RETURNING id;
