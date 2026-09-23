UPDATE demo_snapshots
SET revoked_at = now()
WHERE id = (
    SELECT id FROM demo_snapshots WHERE revoked_at IS NULL ORDER BY id DESC LIMIT 1
)
RETURNING id;
