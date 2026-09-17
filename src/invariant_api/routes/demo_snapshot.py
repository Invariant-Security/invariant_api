"""Demo pública de /containers -- visitante nunca chama rota
operacional (routes/assess.py, routes/reports.py), só estas, que nunca
tocam o ambiente real diretamente. GET aqui é sempre público, de
propósito; POST sempre exige sessão de admin.

Fluxo de publicação: o admin manda `container_id` (Docker ID real,
completo) + os findings já obtidos ao vivo (ainda vêm do frontend
porque não são persistidos hoje -- não tem outro jeito de obtê-los
nesta rodada). O backend NUNCA confia em nome/imagem que o navegador
mandar -- eles são sempre resolvidos aqui contra a lista real atual
(assessment_client.list_containers()), sanitizados (alias fictício
estável por container_id, ver demo_identities.py) e varridos contra
identificadores reais conhecidos (demo_sanitize.py) antes de qualquer
persistência. Isso é recalculado do zero em toda chamada -- nunca
confia num preview anterior.
"""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response
from invariant_contracts import Finding
from pydantic import BaseModel

from invariant_api.auth import require_admin_session
from invariant_api.clients import assessment_client
from invariant_api.demo_identities import get_or_assign_alias
from invariant_api.demo_sanitize import known_real_identifiers, leak_scan
from invariant_api.reports import ConsolidatedAsset, build_ceo_report, build_consolidated_report, build_technical_report
from invariant_api.storage import postgres as db

router = APIRouter(prefix="/demo-snapshot")

_NO_STORE_HEADERS = {"Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache"}


class RealContainerInput(BaseModel):
    container_id: str
    findings: list[Finding] = []


class PublishRequest(BaseModel):
    containers: list[RealContainerInput]


def _sanitize_and_scan(conn, containers: list[RealContainerInput]) -> tuple[list[dict], list[dict], list[str]]:
    live_by_id = {c["id"]: c for c in assessment_client.list_containers()}
    sanitized = []
    unverified = []
    for c in containers:
        live = live_by_id.get(c.container_id)
        if live is None:
            unverified.append(c.container_id)
            continue
        alias_name, alias_image = get_or_assign_alias(conn, container_id=c.container_id)
        sanitized.append(
            {
                "name": alias_name,
                "image": alias_image,
                "findings": [f.model_copy(update={"target": alias_name}).model_dump(mode="json") for f in c.findings],
            }
        )
    issues = leak_scan(sanitized, known_real_identifiers(conn))
    return sanitized, issues, unverified


@router.post("/preview", dependencies=[Depends(require_admin_session)])
def preview(payload: PublishRequest) -> dict:
    with db.connect() as conn:
        sanitized, issues, unverified = _sanitize_and_scan(conn, payload.containers)
    return {
        "ok": not issues and not unverified,
        "containers": sanitized,
        "issues": issues,
        "unverified_container_ids": unverified,
    }


@router.post("/publish", dependencies=[Depends(require_admin_session)])
def publish(payload: PublishRequest) -> dict:
    with db.connect() as conn:
        sanitized, issues, unverified = _sanitize_and_scan(conn, payload.containers)
        if issues or unverified:
            raise HTTPException(
                422,
                {
                    "message": (
                        "Não foi possível publicar a demo. Foram encontrados identificadores do "
                        "ambiente real em campos do snapshot."
                    ),
                    "issues": issues,
                    "unverified_container_ids": unverified,
                },
            )
        db.insert_demo_snapshot(conn, containers=sanitized)
        conn.commit()
    return {"status": "published"}


@router.post("/revoke", dependencies=[Depends(require_admin_session)])
def revoke() -> dict:
    with db.connect() as conn:
        revoked = db.revoke_active_demo_snapshot(conn)
        conn.commit()
    return {"status": "revoked" if revoked else "nothing_to_revoke"}


@router.get("")
def get_snapshot(response: Response) -> dict:
    response.headers.update(_NO_STORE_HEADERS)
    with db.connect() as conn:
        row = db.select_active_demo_snapshot(conn)
    if row is None:
        return {"published_at": None, "containers": []}
    return {"published_at": row["created_at"], "containers": row["containers"]}


@router.get("/report")
def get_report(kind: Literal["ceo", "technical", "consolidated"], target: str | None = None) -> Response:
    """CEO/Técnico continuam por ativo único, exatamente como no fluxo
    ao vivo -- nunca concatena vários containers num
    build_ceo_report()/build_technical_report() só (isso mudaria a
    semântica de compliance %/N-A). `target` é obrigatório pra esses
    dois kinds e é sempre o alias público (nunca um identificador
    real); 404 se não existir no snapshot ativo. `consolidated` cobre a
    frota inteira via build_consolidated_report(), sem target. Nunca
    aceita findings vindos de fora -- só lê o snapshot já persistido.

    Rota pública, mas com rate limit dedicado no nginx (não no
    aplicativo) -- gera PDF no servidor a cada chamada, então precisa
    de proteção contra abuso proporcional ao custo real, sem depender
    de Redis/fila só pra isso.
    """
    with db.connect() as conn:
        row = db.select_active_demo_snapshot(conn)
    if row is None:
        raise HTTPException(404, "Nenhuma demo publicada no momento.")
    containers = row["containers"]

    if kind == "consolidated":
        assets = [
            ConsolidatedAsset(name=c["name"], status="success", findings=[Finding(**f) for f in c["findings"]], error=None)
            for c in containers
        ]
        pdf_bytes = build_consolidated_report(assets)
    else:
        if not target:
            raise HTTPException(422, "O parâmetro 'target' é obrigatório para kind=ceo/technical.")
        container = next((c for c in containers if c["name"] == target), None)
        if container is None:
            raise HTTPException(404, f"Container '{target}' não encontrado no snapshot ativo.")
        builder = build_ceo_report if kind == "ceo" else build_technical_report
        findings = [Finding(**f) for f in container["findings"]]
        pdf_bytes = builder(container["name"], findings, None, None, container["image"])

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={**_NO_STORE_HEADERS, "Content-Disposition": f'inline; filename="invariant-demo-{kind}.pdf"'},
    )
