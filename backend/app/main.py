"""The backend: a small API in front of the database, the permission gate and the agents.

This file only assembles the app. The work is in:

    routes/scans.py      the public API for checks
    routes/system.py     status, practice targets, tool list
    routes/internal.py   endpoints for the agents and the scanner service
    services/agents.py   starts the agent flows in Langflow
    services/...         quality checks, report formats, comparison of two checks
    targets.py           which addresses may be scanned
    db.py                storage

The web page is a separate container (frontend/). It forwards /api/ calls to this one.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from . import db
from .routes import internal, scans, system


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init()
    yield


app = FastAPI(title="Agentic Security Assessment API", lifespan=lifespan)
app.include_router(system.router)
app.include_router(scans.router)
app.include_router(internal.router)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Reports contain text that came from scanned websites, so browsers are told to run no scripts from it."""
    response = await call_next(request)
    if not request.url.path.startswith(("/docs", "/openapi.json")):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response
