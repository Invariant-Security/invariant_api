SELECT id, username, password_hash
FROM admin_users
WHERE username = %(username)s;
