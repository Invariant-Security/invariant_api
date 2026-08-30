-- Email capture for the "subscribe to updates" form on Home.jsx. Storage
-- only for now -- no email/messaging provider wired up yet, that comes
-- once one is contracted.
CREATE TABLE newsletter_subscribers (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
