INSERT INTO demo_snapshots (containers)
VALUES (%(containers)s)
RETURNING id;
