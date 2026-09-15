SELECT id, address, label, tags, created_at
FROM endpoints
WHERE id = %(id)s;
