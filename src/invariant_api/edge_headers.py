"""Headers reservados à infraestrutura interna.

Nenhum desses pode vir do navegador ou de um cliente externo: a borda
(nginx do appliance e nginx-proxy hospedado) zera todos em toda rota que
repassa para dentro, antes de qualquer serviço interno ver a requisição.
Header reservado novo entra AQUI e nos dois nginx -- o teste
tests/test_edge_headers.py confere o nginx do appliance contra esta lista.
"""

RESERVED_INTERNAL_HEADERS = (
    "X-Invariant-Gateway-Token",
    "X-Invariant-Api-Key",
    "X-Invariant-Api-Key-Id",
    "X-Invariant-Principal",
    "X-Invariant-Internal-Token",
)
