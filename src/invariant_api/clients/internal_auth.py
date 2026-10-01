"""Token que o invariant_api apresenta a cada serviço interno.

Um token por serviço (nunca um compartilhado): vazar o do discovery não
autentica no assessment. Lido do ambiente a cada chamada e nunca logado --
a mensagem de erro cita só o NOME da variável.
"""

import os

ASSESSMENT_TOKEN_ENV = "INVARIANT_INTERNAL_ASSESSMENT_TOKEN"
DISCOVERY_TOKEN_ENV = "INVARIANT_INTERNAL_DISCOVERY_TOKEN"
INGESTION_TOKEN_ENV = "INVARIANT_INTERNAL_INGESTION_TOKEN"
SERVICE_TOKEN_ENVS = (ASSESSMENT_TOKEN_ENV, DISCOVERY_TOKEN_ENV, INGESTION_TOKEN_ENV)


def auth_headers(token_env: str) -> dict[str, str]:
    token = os.environ.get(token_env, "")
    if not token:
        raise RuntimeError(f"{token_env} não definido")
    return {"Authorization": f"Bearer {token}"}
