-- One row per checkout attempt from the pricing section on Home.jsx.
-- `amount_cents` is always computed server-side (routes/billing.py), never
-- trusted from the client -- same principle BabyBet's routes_babybet.py
-- already uses for its own Mercado Pago integration.
CREATE TABLE contracts (
    id SERIAL PRIMARY KEY,
    plan TEXT NOT NULL CHECK (plan IN ('single', 'multi')),
    activations INTEGER NOT NULL CHECK (activations > 0),
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'paid')),
    mp_payment_id TEXT,
    contact_name TEXT NOT NULL,
    contact_email TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    paid_at TIMESTAMPTZ
);
