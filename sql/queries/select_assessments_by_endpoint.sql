SELECT public_id, endpoint_id, assessed_ip, assessed_at, source,
       pass_count, fail_count, not_assessed_count, not_applicable_count, compliance_pct
FROM assessment_summaries
WHERE endpoint_id = %(endpoint_id)s
ORDER BY assessed_at DESC;
