INSERT INTO demo_host_snapshots (hosts)
VALUES (%(hosts)s)
RETURNING id;
