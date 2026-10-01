-- lease_expired: uma reserva in_progress parada há mais de 10 min (processo
-- morto no meio) pode ser assumida. Tem que ficar bem acima do tempo máximo
-- de uma avaliação (assessment_client.run_assessment_remote, timeout 30s) --
-- senão uma repetição assumiria a chave com a primeira ainda rodando e
-- dispararia um segundo SSH.
SELECT route, fingerprint, state, response_status, response_body,
       updated_at < now() - interval '10 minutes' AS lease_expired
FROM idempotency_keys
WHERE principal = %(principal)s AND idem_key = %(idem_key)s
FOR UPDATE;
