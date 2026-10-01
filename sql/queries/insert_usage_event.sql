INSERT INTO usage_events (occurred_at, host_kind, host_key, source, endpoint_id, assessment_public_id)
VALUES (%(occurred_at)s, %(host_kind)s, %(host_key)s, %(source)s, %(endpoint_id)s, %(assessment_public_id)s);
