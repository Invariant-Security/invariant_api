INSERT INTO admin_users (username, password_hash)
VALUES (%(username)s, %(password_hash)s)
RETURNING id;
