INSERT INTO discovery_results (endpoint_id, ip, classification, confidence, evidence, scanned_at)
VALUES (%(endpoint_id)s, %(ip)s, %(classification)s, %(confidence)s, %(evidence)s, %(scanned_at)s)
RETURNING id;
