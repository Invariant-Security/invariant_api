DELETE FROM idempotency_keys WHERE created_at < now() - interval '24 hours';
