-- Uma linha por IP distinto já escaneado sob este endpoint, só a rodada
-- mais recente de cada -- um endpoint CIDR pode ter até 254 IPs aqui.
SELECT DISTINCT ON (ip)
    ip, classification, confidence, evidence, scanned_at
FROM discovery_results
WHERE endpoint_id = %(endpoint_id)s
ORDER BY ip, scanned_at DESC;
