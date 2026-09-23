SELECT id, containers, created_at
FROM demo_snapshots
WHERE revoked_at IS NULL
ORDER BY id DESC
LIMIT 1;
