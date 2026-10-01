"""Sobe um app ASGI de verdade (uvicorn numa porta local, em thread) para
testes que precisam de HTTP real entre serviços."""

import threading
import time
from contextlib import contextmanager

import uvicorn


@contextmanager
def live_server(app):
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not server.started:
        assert time.time() < deadline, "servidor não subiu"
        time.sleep(0.02)
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
