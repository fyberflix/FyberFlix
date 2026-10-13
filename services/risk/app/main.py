"""Internal HTTP API for risk-service. Only auth-service may call it."""
from __future__ import annotations

import hmac
import os
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from . import handler


class EvaluateIn(BaseModel):
    spec: str = Field(min_length=1, max_length=40)
    event: dict[str, Any]
    subject_id: str = Field(min_length=1, max_length=128)


def build(engine: handler.Evaluator | None = None, token: str | None = None) -> FastAPI:
    token = token if token is not None else os.environ.get("RISK_SERVICE_TOKEN", "")
    if len(token) < 32:
        raise RuntimeError("RISK_SERVICE_TOKEN must be set (at least 32 characters)")
    if engine is None:
        from .engine import RiskEngine

        engine = RiskEngine(os.environ.get("RULES_DIR", "rules"))
    app = FastAPI(title="fyberflix-risk", docs_url=None, redoc_url=None, openapi_url=None)

    def guard(authorization: str = Header("")):
        if not hmac.compare_digest(authorization, f"Bearer {token}"):
            raise HTTPException(401, "unauthorized")

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.post("/v1/evaluate", dependencies=[Depends(guard)])
    def evaluate(body: EvaluateIn):
        try:
            return handler.evaluate(engine, body.spec, body.event, body.subject_id)
        except handler.BadRequest as e:
            raise HTTPException(e.status, e.msg)

    return app


def app_factory() -> FastAPI:  # uvicorn --factory app.main:app_factory
    return build()
