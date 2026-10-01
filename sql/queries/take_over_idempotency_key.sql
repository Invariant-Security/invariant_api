UPDATE idempotency_keys SET updated_at = now()
WHERE principal = %(principal)s AND idem_key = %(idem_key)s AND state = 'in_progress';
