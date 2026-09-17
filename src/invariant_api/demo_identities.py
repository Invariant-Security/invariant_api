"""Identidades fictícias pra demo pública (routes/demo_snapshot.py).

Namespace deliberadamente registry.example.com (RFC 2606 -- reservado
pra documentação/exemplos, nunca vai resolver pra uma organização real)
em vez de algo tipo ghcr.io/<nome-que-parece-empresa>, que poderia
coincidir com uma org de verdade.

O vínculo container_id (Docker ID real, completo) -> alias é estável:
a mesma vez que um container aparece numa publicação, ele reserva o
próximo alias livre do pool e mantém esse alias em publicações futuras,
mesmo se nome/imagem reais mudarem ou a ordem dos containers mudar.
Continua estável através de rename/restart do MESMO container (o Docker
ID não muda); não promete estabilidade se o container for recriado
(novo Docker ID, pode receber um alias novo).
"""

import psycopg

from invariant_api.storage import postgres as db

DEMO_REGISTRY = "registry.example.com/demo-enterprise"

DEMO_CONTAINER_POOL = [
    ("app-frontend", f"{DEMO_REGISTRY}/frontend:2.4.1"),
    ("app-backend", f"{DEMO_REGISTRY}/backend:1.9.3"),
    ("app-db", f"{DEMO_REGISTRY}/postgres:16.2"),
    ("cache-redis", f"{DEMO_REGISTRY}/redis-cache:7.2.4"),
    ("queue-worker", f"{DEMO_REGISTRY}/job-worker:3.1.0"),
    ("gateway-nginx", f"{DEMO_REGISTRY}/edge-gateway:1.25.3"),
    ("auth-service", f"{DEMO_REGISTRY}/auth-service:1.3.2"),
    ("search-index", f"{DEMO_REGISTRY}/search-index:4.0.1"),
    ("mail-relay", f"{DEMO_REGISTRY}/mail-relay:2.1.0"),
    ("metrics-collector", f"{DEMO_REGISTRY}/metrics-collector:1.7.4"),
    ("cdn-cache", f"{DEMO_REGISTRY}/cdn-cache:3.2.0"),
    ("billing-service", f"{DEMO_REGISTRY}/billing-service:2.6.1"),
    ("notification-worker", f"{DEMO_REGISTRY}/notification-worker:1.4.0"),
    ("session-store", f"{DEMO_REGISTRY}/session-store:6.2.0"),
    ("audit-logger", f"{DEMO_REGISTRY}/audit-logger:1.0.3"),
]


def get_or_assign_alias(conn: psycopg.Connection, *, container_id: str) -> tuple[str, str]:
    """Commita a atribuição imediatamente, mesmo quando chamada durante
    um /preview que pode nunca virar publicação -- é um efeito colateral
    aceitável e pedido explicitamente: o mesmo alias reservado no
    preview tem que ser o mesmo usado no publish depois. Nunca dá
    rollback dessa atribuição por causa do leak scan falhar em seguida
    -- reservar o alias e decidir publicar são passos independentes.
    """
    existing = db.get_demo_alias(conn, container_id=container_id)
    if existing:
        return existing["alias_name"], existing["alias_image"]

    used_names = set(db.list_demo_alias_names(conn))
    n = len(used_names) + 1
    candidates = [(name, image) for name, image in DEMO_CONTAINER_POOL if name not in used_names]
    # Pool esgotado -- degrada pra um nome numerado em vez de falhar.
    candidates.append((f"extra-service-{n}", f"{DEMO_REGISTRY}/service:{n}.0.0"))

    for alias_name, alias_image in candidates:
        try:
            db.insert_demo_alias(conn, container_id=container_id, alias_name=alias_name, alias_image=alias_image)
            conn.commit()
            return alias_name, alias_image
        except psycopg.errors.UniqueViolation:
            # Corrida (duas atribuições concorrentes tentando o mesmo
            # candidato) -- tenta o próximo em vez de propagar o erro.
            # Hoje só existe um admin, mas isso não deveria depender
            # disso pra funcionar corretamente.
            conn.rollback()
            continue
    raise RuntimeError("não foi possível atribuir um alias de demo")  # inatingível dado o fallback numerado
