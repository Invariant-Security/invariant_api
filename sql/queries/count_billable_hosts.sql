-- Unidades de cobrança de um período: identidades DISTINTAS, não eventos.
-- Limites [start, end) calculados em UTC pelo chamador
-- (invariant_contracts.usage.period_bounds) -- nunca date_trunc, que
-- dependeria do fuso da sessão.
SELECT host_kind, COUNT(DISTINCT host_key)
FROM usage_events
WHERE occurred_at >= %(start)s AND occurred_at < %(end)s
GROUP BY host_kind;
