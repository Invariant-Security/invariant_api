"""Avaliação de host Linux e registro do que ela consumiu (F1).

Fluxo de uma avaliação, nesta ordem:
  1. validar o pedido e resolver o alvo (resolve_target) -- antes de
     qualquer conexão de rede: IP fora do alvo ou não descoberto é recusado;
  2. resolver a Idempotency-Key (reserve) -- antes de executar, para que
     repetir a mesma chave nunca dispare um segundo SSH;
  3. executar a avaliação remota (run_remote), FORA de qualquer transação;
  4. só com resultado válido, uma transação curta (persist) grava juntos o
     resumo, o evento de consumo, o evento de domínio assessment.completed e
     o fechamento da chave -- ou nada.
Falha sem efeito persistido libera a chave (release).

Consumo != execução: cada avaliação concluída gera um evento bruto em
usage_events; a cobrança conta identidades distintas por período
(storage.count_billable_hosts).
"""

import hashlib
import ipaddress
import json
from datetime import datetime, timezone

import httpx
from fastapi import HTTPException
from invariant_contracts import Finding, v1
from invariant_contracts.usage import normalize_host_ip

from invariant_api.clients import assessment_client
from invariant_api.reports import compliance_pct, split_findings
from invariant_api.storage import postgres as db

HOST_KIND = "linux_host"
ASSESSMENT_COMPLETED = "assessment.completed"
CREATE_ROUTE = "POST /endpoints/{id}/assessments"


def api_error(status: int, code: v1.ErrorCode, message: str) -> HTTPException:
    return HTTPException(status, {"code": code.value, "message": message})


# --- 1. alvo -----------------------------------------------------------------

def resolve_target(conn, endpoint_id: int, requested_ip) -> tuple[dict, str]:
    """(endpoint, IP normalizado a avaliar). Nenhuma conexão de rede aqui."""
    endpoint = db.select_endpoint_by_id(conn, id=endpoint_id)
    if endpoint is None:
        raise api_error(404, v1.ErrorCode.not_found, f"alvo {endpoint_id} não encontrado")
    discovered = [normalize_host_ip(r["ip"]) for r in db.select_latest_discovery_results_by_endpoint(conn, endpoint_id=endpoint_id)]
    if not discovered:
        raise api_error(422, v1.ErrorCode.target_not_discovered, f"alvo {endpoint_id} ainda não foi descoberto")
    if requested_ip is None:
        return endpoint, discovered[0]
    ip = normalize_host_ip(str(requested_ip))
    if ipaddress.ip_address(ip) not in ipaddress.ip_network(endpoint["address"], strict=False):
        raise api_error(422, v1.ErrorCode.ip_not_in_target, f"{ip} não pertence ao alvo {endpoint['address']}")
    if ip not in discovered:
        raise api_error(422, v1.ErrorCode.target_not_discovered, f"{ip} não está entre os hosts descobertos deste alvo")
    return endpoint, ip


# --- 2. idempotência ---------------------------------------------------------

def fingerprint(route: str, endpoint_id: int, request: v1.AssessmentRequest) -> str:
    """Identidade do pedido para detectar "mesma chave, outro pedido".
    Nunca inclui credenciais: nada derivado de senha/chave vai para o banco."""
    canonical = {
        "route": route,
        "endpoint_id": endpoint_id,
        "ip": None if request.ip is None else normalize_host_ip(str(request.ip)),
        "port": request.ssh.port,
        "username": request.ssh.username,
        "auth_method": request.ssh.auth_method,
    }
    return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()


def reserve(principal: str, key: str, route: str, fp: str) -> dict | None:
    """Reserva a chave antes de executar. None = pode executar; dict =
    resposta já registrada para repetir (status, body). 422 se a mesma chave
    veio com outro pedido; 409 se a mesma chave está em execução agora."""
    for _ in range(2):  # 2ª volta só se a linha sumiu entre o INSERT e o SELECT
        with db.connect() as conn:
            db.purge_expired_idempotency_keys(conn)
            if db.insert_idempotency_key(conn, principal=principal, idem_key=key, route=route, fingerprint=fp):
                return None
            row = db.select_idempotency_key_for_update(conn, principal=principal, idem_key=key)
            if row is None:
                continue
            if row["route"] != route or row["fingerprint"] != fp:
                raise api_error(422, v1.ErrorCode.idempotency_mismatch,
                                "Idempotency-Key já usada com um pedido diferente")
            if row["state"] == "completed":
                return {"status": row["response_status"], "body": row["response_body"]}
            if row["lease_expired"]:
                db.take_over_idempotency_key(conn, principal=principal, idem_key=key)
                return None
            raise api_error(409, v1.ErrorCode.idempotency_in_progress,
                            "uma requisição com esta Idempotency-Key está em execução")
    raise api_error(409, v1.ErrorCode.idempotency_in_progress, "Idempotency-Key em disputa, tente de novo")


def release(principal: str, key: str) -> None:
    with db.connect() as conn:
        db.delete_idempotency_key(conn, principal=principal, idem_key=key)


# --- 3. execução -------------------------------------------------------------

_ASSESSMENT_ERRORS = {
    401: (401, v1.ErrorCode.ssh_auth_failed),
    502: (502, v1.ErrorCode.target_unreachable),
    504: (504, v1.ErrorCode.assessment_timeout),
}


def run_remote(ip: str, ssh: v1.SSHCredentials) -> dict:
    try:
        return assessment_client.run_assessment_remote(
            host=ip,
            port=ssh.port,
            username=ssh.username,
            auth_method=ssh.auth_method,
            key_material=ssh.private_key,
            password=ssh.password,
        )
    except httpx.HTTPStatusError as e:
        status, code = _ASSESSMENT_ERRORS.get(e.response.status_code, (502, v1.ErrorCode.upstream_error))
        raise api_error(status, code, f"avaliação falhou ({e.response.status_code})") from e
    except httpx.HTTPError as e:
        raise api_error(502, v1.ErrorCode.upstream_error, "serviço de avaliação indisponível") from e


# --- 4. persistência ---------------------------------------------------------

def _classify(findings: list[Finding]) -> tuple[dict, list[tuple[Finding, str]]]:
    applicable_pass, applicable_fail, not_assessed, not_applicable = split_findings(findings)
    summary = {
        "passed": len(applicable_pass),
        "failed": len(applicable_fail),
        "not_assessed": len(not_assessed),
        "not_applicable": len(not_applicable),
        "compliance_pct": compliance_pct(applicable_pass, applicable_fail),
    }
    result_of = {}
    for group, result in ((applicable_pass, "pass"), (applicable_fail, "fail"),
                          (not_assessed, "not_assessed"), (not_applicable, "not_applicable")):
        for f in group:
            result_of[id(f)] = result
    return summary, [(f, result_of[id(f)]) for f in findings]


def to_v1_findings(classified: list[tuple[Finding, str]]) -> list[dict]:
    return [
        v1.Finding(
            control_id=f.external_id,
            title=f.control_title,
            benchmark=f.document_name,
            benchmark_version=f.document_version,
            result=result,
            level=f.level,
            scored=f.scored,
            evidence=f.evidence_output,
            remediation=f.remediation,
            collected_at=f.collected_at,
        ).model_dump(mode="json")
        for f, result in classified
    ]


def envelope(*, public_id, endpoint_id: int, assessed_ip: str, assessed_at, source: str,
             summary: dict, findings: list[dict] | None, omitted_reason: str | None) -> dict:
    return v1.AssessmentEnvelope(
        assessment_id=public_id,
        target_id=endpoint_id,
        assessed_ip=assessed_ip,
        assessed_at=assessed_at,
        source=source,
        summary=v1.Summary(**summary),
        findings=findings,
        findings_omitted_reason=omitted_reason,
    ).model_dump(mode="json")


def persist(*, endpoint: dict, ip: str, findings: list[Finding], source: str,
            idempotency: tuple[str, str] | None = None) -> dict:
    """Uma transação: resumo + consumo + evento de domínio (+ fecha a chave).
    Qualquer falha desfaz tudo. Devolve o envelope v1 COM os achados (só
    para esta resposta -- o que fica guardado na chave nunca tem achados)."""
    summary, classified = _classify(findings)
    assessed_at = datetime.now(timezone.utc)
    with db.connect() as conn, conn.transaction():
        record = db.insert_assessment_record(
            conn,
            endpoint_id=endpoint["id"],
            target_type=HOST_KIND,
            pass_count=summary["passed"],
            fail_count=summary["failed"],
            not_assessed_count=summary["not_assessed"],
            not_applicable_count=summary["not_applicable"],
            compliance_pct=summary["compliance_pct"],
            assessed_at=assessed_at,
            assessed_ip=ip,
            source=source,
        )
        db.insert_usage_event(
            conn,
            occurred_at=record["assessed_at"],
            host_kind=HOST_KIND,
            host_key=normalize_host_ip(ip),
            source=source,
            endpoint_id=endpoint["id"],
            assessment_public_id=record["public_id"],
        )
        db.insert_domain_event(
            conn,
            event_type=ASSESSMENT_COMPLETED,
            occurred_at=record["assessed_at"],
            payload={
                "assessment_id": str(record["public_id"]),
                "source": source,
                "target": {"kind": HOST_KIND, "target_id": endpoint["id"], "address": endpoint["address"],
                           "assessed_ip": ip},
                "summary": summary,
            },
        )
        common = {"public_id": record["public_id"], "endpoint_id": endpoint["id"], "assessed_ip": ip,
                  "assessed_at": record["assessed_at"], "source": source, "summary": summary}
        if idempotency is not None:
            principal, key = idempotency
            stored = envelope(**common, findings=None, omitted_reason="not_stored")
            if not db.complete_idempotency_key(conn, principal=principal, idem_key=key,
                                               response_status=200, response_body=stored):
                raise RuntimeError("reserva da Idempotency-Key perdida antes de concluir")
    return envelope(**common, findings=to_v1_findings(classified), omitted_reason=None)
