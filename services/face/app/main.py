"""Internal HTTP API for face-service. Only auth-service may call it."""
from __future__ import annotations

import hmac
import uuid

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile

from .config import Settings
from .crypto import KeyRing
from .service import FaceService
from .state import RedisState
from .store import PostgresStore
from .vision import OpenCVVision

MAX_FRAME_BYTES = 600_000


def build() -> FastAPI:
    s = Settings.from_env()
    svc = FaceService(s, OpenCVVision(s), PostgresStore(s.database_url),
                      RedisState(s.redis_url), KeyRing(s.keys, s.active_key_id))
    app = FastAPI(title="fyberflix-face", docs_url=None, redoc_url=None, openapi_url=None)

    def guard(authorization: str = Header("")):
        if not hmac.compare_digest(authorization, f"Bearer {s.service_token}"):
            raise HTTPException(401, "unauthorized")

    def ref_of(v: str) -> str:
        try:
            return str(uuid.UUID(v))
        except ValueError:
            raise HTTPException(422, "subject_ref must be a UUID")

    def read_frames(files: list[UploadFile]) -> list[bytes]:
        out = []
        for f in files[: s.max_frames + 1]:
            b = f.file.read(MAX_FRAME_BYTES + 1)
            if len(b) > MAX_FRAME_BYTES:
                raise HTTPException(413, "frame too large")
            out.append(b)
        return out

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.post("/v1/challenges", dependencies=[Depends(guard)])
    def challenge(subject_ref: str = Form(...), purpose: str = Form(...)):
        if purpose not in ("enroll", "verify"):
            raise HTTPException(422, "purpose must be enroll or verify")
        c = svc.create_challenge(ref_of(subject_ref), purpose)
        return {"challenge_id": c.id, "steps": list(c.steps), "expires_in": s.challenge_ttl}

    @app.post("/v1/enroll", dependencies=[Depends(guard)])
    def enroll(subject_ref: str = Form(...), challenge_id: str = Form(...), frames: list[UploadFile] = File(...)):
        r = svc.enroll(ref_of(subject_ref), challenge_id, read_frames(frames))
        return {"ok": r.ok, "reason": r.reason}

    @app.post("/v1/verify", dependencies=[Depends(guard)])
    def verify(subject_ref: str = Form(...), challenge_id: str = Form(...), frames: list[UploadFile] = File(...)):
        r = svc.verify(ref_of(subject_ref), challenge_id, read_frames(frames))
        return {"ok": r.ok, "reason": r.reason}          # score is deliberately not returned

    @app.delete("/v1/templates/{subject_ref}", dependencies=[Depends(guard)])
    def erase(subject_ref: str):
        return {"deleted": svc.delete(ref_of(subject_ref))}

    return app


app = build()
