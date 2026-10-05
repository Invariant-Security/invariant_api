"""Carga inicial dos benchmarks CIS, rodada dentro do container api por
bootstrap-documents.sh (`python -m invariant_api.bootstrap_documents <doc>...`).
Chama direto as funções de routes/ingest.py: as rotas HTTP exigem sessão de
admin, que um appliance recém-instalado ainda não tem.

Por documento: normalize primeiro (sucede se já ingerido), senão
fetch -> extract -> normalize. Falha de um documento é só logada; os outros
continuam e o exit code é sempre 0.
"""

import sys

from invariant_api.routes import ingest


def log(msg: str) -> None:
    print(f"[bootstrap-documents] {msg}", flush=True)


def bootstrap(doc: str) -> None:
    # /ingest/normalize espera o slug sem "cis-" e com "_" (ubuntu_linux_24_04);
    # fetch/extract usam a chave com hífen.
    slug = doc.removeprefix("cis-").replace("-", "_")
    try:
        ingest.normalize(slug)
        log(f"{doc} já ingerido, pulando.")
        return
    except Exception:
        pass
    log(f"Ingerindo {doc} (fetch + extract + normalize, primeira vez -- pode levar ~30s)...")
    for step, call, arg in (("fetch", ingest.fetch, doc), ("extract", ingest.extract, doc), ("normalize", ingest.normalize, slug)):
        try:
            call(arg)
        except Exception as exc:
            log(f"AVISO: {step} de {doc} falhou, pulando ({exc!r}).")
            return
    log(f"{doc} ingerido com sucesso.")


def main(docs: list[str]) -> None:
    for doc in docs:
        bootstrap(doc)
    log("Bootstrap de documentos concluído.")


if __name__ == "__main__":
    main(sys.argv[1:])
