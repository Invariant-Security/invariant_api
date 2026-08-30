SELECT id, plan, activations, amount_cents, status, contact_name, contact_email, created_at, paid_at
FROM contracts
WHERE id = %(id)s;
