INSERT INTO domain_events (event_type, occurred_at, payload)
VALUES (%(event_type)s, %(occurred_at)s, %(payload)s)
RETURNING event_id;
