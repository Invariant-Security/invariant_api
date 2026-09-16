INSERT INTO leads (name, email, company, role, target_scope, environment_size, primary_need, message)
VALUES (%(name)s, %(email)s, %(company)s, %(role)s, %(target_scope)s, %(environment_size)s, %(primary_need)s, %(message)s)
RETURNING id;
