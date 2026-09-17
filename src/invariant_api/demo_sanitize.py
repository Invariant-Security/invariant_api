"""Leak scan pra publicação da demo pública (routes/demo_snapshot.py) --
compara o snapshot já sanitizado (nomes/imagens já trocados pelo alias)
contra uma lista de identificadores REAIS conhecidos pelo próprio
sistema, não um detector genérico de PII/segredo (isso seria complexo e
pouco confiável pro problema real, que é vazar nome/imagem/endereço do
ambiente do Victor, não qualquer string sensível em abstrato).

Termos genéricos de infra (postgres, nginx, redis, frontend, backend,
versões...) são explicitamente filtrados antes de entrar na lista de
identificadores conhecidos -- eles aparecem tanto no snapshot fictício
quanto em evidence legítima do CIS, e tratá-los como sensíveis geraria
falso positivo constante, bloqueando publicações que não vazam nada de
verdade.
"""

import re
import socket

import psycopg

from invariant_api.clients import assessment_client
from invariant_api.storage import postgres as db

_GENERIC_IMAGE_TERMS = {
    "postgres", "postgresql", "nginx", "redis", "mysql", "mariadb", "mongo", "mongodb",
    "frontend", "backend", "web", "api", "app", "worker", "cache", "gateway", "service",
    "db", "queue", "job", "edge", "proxy", "alpine", "slim", "bullseye", "bookworm",
    "debian", "ubuntu", "centos", "fedora", "node", "python", "golang", "java",
    "ghcr.io", "docker.io", "index.docker.io", "quay.io", "library", "latest",
}
_VERSION_RE = re.compile(r"^v?\d+(\.\d+){0,3}([-.].+)?$")
_MIN_TOKEN_LENGTH = 4

# Exceção documentada e deliberada: não vem de nenhuma tabela do banco
# (não há de onde derivar isso do estado do sistema) -- são domínios e
# nomes de projeto reais conhecidos desta VPS, mantidos aqui à mão.
_KNOWN_INTERNAL_DOMAINS = [
    "invariantsec.org",
    "forjadosdias.tech",
    "forjadosdias.com.br",
    "victordg.dev.br",
    "tamois.com.br",
    "aprovadonaoab.com.br",
]
_KNOWN_PROJECT_NAMES = ["tamois", "estudeoab", "amanuense", "naoesqueci", "liliankaliaki", "babybet"]


def _distinctive_image_tokens(image: str) -> list[str]:
    """Só os pedaços do path da imagem que não são vocabulário genérico
    de infra nem parecem número de versão -- de
    "ghcr.io/tamois-ia-juridica/tamois:v1", só "tamois-ia-juridica" e
    "tamois" sobrevivem (ghcr.io é registry genérico, v1 é versão).
    """
    tokens = re.split(r"[/:]+", image)
    out = []
    for raw in tokens:
        t = raw.strip().lower()
        if len(t) < _MIN_TOKEN_LENGTH or t in _GENERIC_IMAGE_TERMS or _VERSION_RE.match(t):
            continue
        out.append(raw)
    return out


def known_real_identifiers(conn: psycopg.Connection) -> list[tuple[str, str]]:
    """[(token, categoria)] -- identificadores distintivos do ambiente
    real atual. Recalculado a cada preview/publish, nunca cacheado --
    um container pode ter sido criado/removido desde a última chamada.
    """
    tokens: list[tuple[str, str]] = []

    for c in assessment_client.list_containers():
        tokens.append((c["name"], "container_name"))
        distinctive = _distinctive_image_tokens(c["image"])
        # A string completa da imagem só entra como identificador
        # conhecido se ela tiver pelo menos um pedaço distintivo (não
        # genérico/versão) -- senão uma imagem 100% genérica (ex.:
        # "postgres:16", usada pelo próprio Postgres do Invariant, não
        # de um cliente) vira falso positivo contra qualquer alias
        # fictício com versão parecida (ex.: ".../postgres:16.2" bate
        # substring com "postgres:16"). Confirmado com um vazamento
        # falso real durante teste em teste.invariantsec.org.
        if distinctive:
            tokens.append((c["image"], "container_image"))
            for t in distinctive:
                tokens.append((t, "container_image_org"))

    for e in db.select_endpoints(conn):
        tokens.append((e["address"], "endpoint_address"))
        label = e.get("label")
        if label and len(label) >= _MIN_TOKEN_LENGTH and label.lower() not in _GENERIC_IMAGE_TERMS:
            tokens.append((label, "endpoint_label"))

    tokens.append((socket.gethostname(), "hostname"))
    tokens += [(d, "internal_domain") for d in _KNOWN_INTERNAL_DOMAINS]
    tokens += [(p, "known_project_name") for p in _KNOWN_PROJECT_NAMES]

    return [(t, cat) for t, cat in tokens if t and len(t) >= _MIN_TOKEN_LENGTH]


def _scan_field(value, *, field_path: str, known_tokens: list[tuple[str, str]], issues: list[dict], seen: set[tuple[str, str]]) -> None:
    if not isinstance(value, str) or not value:
        return
    lowered = value.lower()
    for token, category in known_tokens:
        key = (field_path, category)
        if key in seen:
            continue
        if token.lower() in lowered:
            seen.add(key)
            issues.append({"field": field_path, "category": category})


def leak_scan(sanitized_containers: list[dict], known_tokens: list[tuple[str, str]]) -> list[dict]:
    """Navega o snapshot já sanitizado campo a campo (não uma busca numa
    string gigante só) pra poder apontar ONDE cada identificador real
    apareceu -- cobre nome/imagem do container e todo campo de texto de
    cada finding (evidence_output, remediation, raw_artifact_path,
    etc). Retorna [] se limpo; senão, uma entrada por (campo, categoria)
    batida, sem ecoar o valor real batido de volta -- só o suficiente
    pro admin achar e corrigir.
    """
    issues: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for i, container in enumerate(sanitized_containers):
        _scan_field(container.get("name"), field_path=f"containers[{i}].name", known_tokens=known_tokens, issues=issues, seen=seen)
        _scan_field(container.get("image"), field_path=f"containers[{i}].image", known_tokens=known_tokens, issues=issues, seen=seen)
        for j, finding in enumerate(container.get("findings") or []):
            for key, value in finding.items():
                _scan_field(
                    value,
                    field_path=f"containers[{i}].findings[{j}].{key}",
                    known_tokens=known_tokens,
                    issues=issues,
                    seen=seen,
                )
    return issues
