INSERT INTO newsletter_subscribers (email)
VALUES (%(email)s)
ON CONFLICT (email) DO NOTHING
RETURNING id;
