INSERT INTO contracts (plan, activations, amount_cents, contact_name, contact_email)
VALUES (%(plan)s, %(activations)s, %(amount_cents)s, %(contact_name)s, %(contact_email)s)
RETURNING id;
