SELECT id, hosts, created_at
FROM demo_host_snapshots
WHERE revoked_at IS NULL
ORDER BY id DESC
LIMIT 1;
