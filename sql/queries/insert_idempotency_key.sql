INSERT INTO idempotency_keys (principal, idem_key, route, fingerprint, state)
VALUES (%(principal)s, %(idem_key)s, %(route)s, %(fingerprint)s, 'in_progress')
ON CONFLICT (principal, idem_key) DO NOTHING
RETURNING principal;
