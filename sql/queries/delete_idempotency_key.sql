DELETE FROM idempotency_keys
WHERE principal = %(principal)s AND idem_key = %(idem_key)s AND state = 'in_progress';
