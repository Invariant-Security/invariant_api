"""FastAPI application entrypoint -- the control plane. Registers the demo
routes (ported unchanged from the monolith's api/main.py) plus the two new
orchestration routers (assess, ingest) that replace the monolith's CLI
commands + assess_target()'s in-process calls with HTTP calls to
invariant_assessment/invariant_ingestion.
"""

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from invariant_api.config import load_dotenv
from invariant_api.routes import assess, billing, demo, ingest, newsletter

load_dotenv()

app = FastAPI(title="Invariant API")

_default_origins = "http://localhost:5173,http://127.0.0.1:5173"
allow_origins = [
    origin.strip()
    for origin in os.environ.get("INVARIANT_API_CORS_ORIGINS", _default_origins).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


app.include_router(demo.router)
app.include_router(assess.router)
app.include_router(ingest.router)
app.include_router(billing.router)
app.include_router(newsletter.router)
