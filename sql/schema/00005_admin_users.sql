-- Appliance admin. Único admin garantido na camada de app (POST
-- /auth/setup retorna 409 se já existir uma linha aqui) -- não há
-- escritor concorrente num appliance single-tenant, então uma constraint
-- extra pra impedir uma segunda linha seria defesa não pedida.
CREATE TABLE admin_users (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
