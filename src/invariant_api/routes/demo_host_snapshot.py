"""Demo pública de /endpoints -- espelha routes/demo_snapshot.py's
design pra hosts Linux em vez de containers Docker. GET aqui é sempre
público, de propósito; POST sempre exige sessão de admin.

Fonte autorizada de publicação: só endpoints dentro da faixa de IP
reservada e isolada do Invariant Demo Lab de Hosts Linux (LXD, ver
demo_lab/docs/networking.md -- `10.89.77.0/24`, sub-rede dedicada,
firewall próprio bloqueando qualquer alcance a infraestrutura real).
Essa faixa é o ÚNICO critério de elegibilidade, checado aqui no
backend via `is_demo_endpoint` (nunca só escondido no frontend) -- ver
`not_demo` em `_sanitize_and_scan()`.

Fluxo de publicação: o admin manda `endpoint_id` (id real, permanente,
da tabela `endpoints`) + os findings já obtidos ao vivo via
`/endpoints/{id}/assess` (mesma limitação de `demo_snapshot.py`: não
persistidos, vêm do frontend nesta rodada). O backend NUNCA confia em
label/endereço/elegibilidade que o navegador mandar -- tudo é resolvido
aqui contra o estado real atual (`db.select_endpoint_by_id`),
sanitizado (alias fictício estável por `endpoint_id`, ver
demo_identities.py's `get_or_assign_host_alias`) e varrido contra
identificadores reais conhecidos (demo_sanitize.py, defesa em
profundidade) antes de qualquer persistência. Snapshot e ciclo de vida
(preview/publish/revoke) totalmente separados de `demo_snapshot.py`'s
containers -- `image` não existe pra host, e publicar/revogar hosts é
independente de publicar/revogar containers.
"""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response
from invariant_contracts import Finding
from pydantic import BaseModel

from invariant_api.auth import require_admin_session
from invariant_api.demo_identities import get_or_assign_host_alias
from invariant_api.demo_sanitize import is_demo_endpoint, known_real_identifiers, leak_scan_hosts, redact_real_identity, verify_redaction
from invariant_api.reports import ConsolidatedAsset, build_ceo_report, build_consolidated_report, build_technical_report
from invariant_api.storage import postgres as db

router = APIRouter(prefix="/demo-host-snapshot")

_NO_STORE_HEADERS = {"Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache"}


class RealHostInput(BaseModel):
    endpoint_id: int
    findings: list[Finding] = []


class PublishRequest(BaseModel):
    hosts: list[RealHostInput]


def _sanitize_and_scan(
    conn, hosts: list[RealHostInput]
) -> tuple[list[dict], list[dict], list[str], list[str], list[dict]]:
    sanitized = []
    unverified = []
    not_demo = []
    all_replacements: list[tuple[str, str]] = []
    for h in hosts:
        endpoint = db.select_endpoint_by_id(conn, id=h.endpoint_id)
        if endpoint is None:
            unverified.append(str(h.endpoint_id))
            continue
        # Faixa de IP reservada é o ÚNICO critério de elegibilidade --
        # nunca inferido por label. Fora dela = não publicável, sempre,
        # mesmo que o admin já tenha avaliado esse endpoint.
        if not is_demo_endpoint(endpoint["address"]):
            not_demo.append(str(h.endpoint_id))
            continue
        alias_label, alias_address = get_or_assign_host_alias(conn, endpoint_id=h.endpoint_id)
        # Substitui endereço/label reais em TODO campo de texto do
        # finding, não só `target` -- sem isso, evidence_output podia
        # citar o IP/hostname real do host por acaso, quebrando a
        # coerência da identidade pública mostrada ao lado.
        replacements = [(endpoint["address"], alias_address)]
        label = endpoint.get("label")
        if label:
            replacements.append((label, alias_label))
        all_replacements.extend(replacements)
        redacted_findings = [redact_real_identity(f, replacements).model_dump(mode="json") for f in h.findings]
        sanitized.append({"name": alias_label, "address": alias_address, "findings": redacted_findings})
    issues = leak_scan_hosts(sanitized, known_real_identifiers(conn))
    redaction_issues = verify_redaction(sanitized, all_replacements)
    return sanitized, issues, unverified, not_demo, redaction_issues


@router.post("/preview", dependencies=[Depends(require_admin_session)])
def preview(payload: PublishRequest) -> dict:
    with db.connect() as conn:
        sanitized, issues, unverified, not_demo, redaction_issues = _sanitize_and_scan(conn, payload.hosts)
    return {
        "ok": not issues and not unverified and not not_demo and not redaction_issues,
        "hosts": sanitized,
        "issues": issues,
        "unverified_endpoint_ids": unverified,
        "not_demo_endpoint_ids": not_demo,
        "redaction_issues": redaction_issues,
    }


@router.post("/publish", dependencies=[Depends(require_admin_session)])
def publish(payload: PublishRequest) -> dict:
    with db.connect() as conn:
        sanitized, issues, unverified, not_demo, redaction_issues = _sanitize_and_scan(conn, payload.hosts)
        if issues or unverified or not_demo:
            raise HTTPException(
                422,
                {
                    "message": (
                        "Não foi possível publicar a demo. Foram encontrados identificadores do "
                        "ambiente real em campos do snapshot, ou algum ativo enviado não pertence "
                        "ao ambiente demonstrativo e não pode ser publicado."
                    ),
                    "issues": issues,
                    "unverified_endpoint_ids": unverified,
                    "not_demo_endpoint_ids": not_demo,
                },
            )
        if redaction_issues:
            raise HTTPException(
                422,
                {
                    "message": (
                        "Não foi possível publicar a demo: a própria sanitização falhou -- o "
                        "endereço/label real de um host do Demo Lab sobreviveu num campo do "
                        "snapshot depois da substituição pelo alias."
                    ),
                    "redaction_issues": redaction_issues,
                },
            )
        db.insert_demo_host_snapshot(conn, hosts=sanitized)
        conn.commit()
    return {"status": "published"}


@router.post("/revoke", dependencies=[Depends(require_admin_session)])
def revoke() -> dict:
    with db.connect() as conn:
        revoked = db.revoke_active_demo_host_snapshot(conn)
        conn.commit()
    return {"status": "revoked" if revoked else "nothing_to_revoke"}


@router.get("")
def get_snapshot(response: Response) -> dict:
    response.headers.update(_NO_STORE_HEADERS)
    with db.connect() as conn:
        row = db.select_active_demo_host_snapshot(conn)
    if row is None:
        return {"published_at": None, "hosts": []}
    return {"published_at": row["created_at"], "hosts": row["hosts"]}


@router.get("/report")
def get_report(kind: Literal["ceo", "technical", "consolidated"], target: str | None = None) -> Response:
    """Mesmo design de demo_snapshot.py's get_report -- CEO/Técnico por
    ativo único via `target` (alias público, nunca identificador real),
    `consolidated` cobre a frota inteira. Nunca aceita findings vindos
    de fora -- só lê o snapshot já persistido. `hostname`/`primary_ip`
    do relatório usam o alias (label/endereço fictícios) no lugar do
    `container_image` que não existe pra host.

    Rota pública, mas com rate limit dedicado no nginx (não no
    aplicativo) -- mesma justificativa de custo de `demo_snapshot.py`.
    """
    with db.connect() as conn:
        row = db.select_active_demo_host_snapshot(conn)
    if row is None:
        raise HTTPException(404, "Nenhuma demo publicada no momento.")
    hosts = row["hosts"]

    if kind == "consolidated":
        assets = [
            ConsolidatedAsset(name=h["name"], status="success", findings=[Finding(**f) for f in h["findings"]], error=None)
            for h in hosts
        ]
        pdf_bytes = build_consolidated_report(assets)
    else:
        if not target:
            raise HTTPException(422, "O parâmetro 'target' é obrigatório para kind=ceo/technical.")
        host = next((h for h in hosts if h["name"] == target), None)
        if host is None:
            raise HTTPException(404, f"Host '{target}' não encontrado no snapshot ativo.")
        builder = build_ceo_report if kind == "ceo" else build_technical_report
        findings = [Finding(**f) for f in host["findings"]]
        pdf_bytes = builder(host["name"], findings, host["name"], host["address"], None)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={**_NO_STORE_HEADERS, "Content-Disposition": f'inline; filename="invariant-demo-host-{kind}.pdf"'},
    )
