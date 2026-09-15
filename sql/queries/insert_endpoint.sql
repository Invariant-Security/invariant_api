INSERT INTO endpoints (address, label, tags)
VALUES (%(address)s, %(label)s, %(tags)s)
RETURNING id;
