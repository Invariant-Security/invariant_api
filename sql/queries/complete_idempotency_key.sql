UPDATE idempotency_keys
SET state = 'completed', response_status = %(response_status)s, response_body = %(response_body)s, updated_at = now()
WHERE principal = %(principal)s AND idem_key = %(idem_key)s AND state = 'in_progress';
