-- Lead comercial captado pelo formulário "Fale com a Invariant" da home
-- (substituiu a seção de planos públicos -- venda agora é 1:1 com o
-- cliente). target_scope/environment_size/primary_need guardam códigos
-- fechados (ver routes/leads.py's Literal), não o texto em português
-- exibido no formulário. Sem UNIQUE em email -- a mesma pessoa pode
-- mandar o formulário mais de uma vez.
--
-- slack_notified_at só é preenchido quando a notificação realmente sai
-- (NULL não significa erro, só "ainda não confirmado"). slack_last_error
-- guarda um código curto e estável (nunca stack trace/URL do webhook) --
-- junto com slack_notify_attempts, dá pra identificar lead pendente de
-- reenvio manual sem depender de estado em memória.
CREATE TABLE leads (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    company TEXT NOT NULL,
    role TEXT,
    target_scope TEXT NOT NULL,
    environment_size TEXT,
    primary_need TEXT,
    message TEXT,
    source TEXT NOT NULL DEFAULT 'invariantsec.org',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    slack_notified_at TIMESTAMPTZ,
    slack_notify_attempts INTEGER NOT NULL DEFAULT 0,
    slack_last_error TEXT
);
