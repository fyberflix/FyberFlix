from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    # models
    models_dir: Path = Path("models")
    detector_file: str = "face_detection_yunet_2023mar.onnx"
    recognizer_file: str = "face_recognition_sface_2021dec.onnx"
    # frame quality gates
    min_det_score: float = 0.90
    min_face_px: int = 112
    min_sharpness: float = 60.0
    max_image_side: int = 1280
    # liveness (challenge-response on head yaw)
    center_ratio: float = 0.12
    turn_ratio: float = 0.22
    chain_threshold: float = 0.45   # consecutive frames must be the same person
    min_frames: int = 6
    max_frames: int = 24
    min_center_frames: int = 3
    challenge_ttl: int = 120
    # matching (cosine). Starting point: calibrate FAR/FRR on your own data.
    match_threshold: float = 0.40
    max_failures: int = 5
    failure_window: int = 900
    # secrets / infra
    keys: dict[str, bytes] | None = None
    active_key_id: str = ""
    service_token: str = ""
    redis_url: str = ""
    database_url: str = ""

    @staticmethod
    def from_env() -> "Settings":
        # FACE_KEYS="k1:<base64 32 bytes>,k2:<base64 32 bytes>"; FACE_ACTIVE_KEY="k2"
        keys = {}
        for item in filter(None, os.environ.get("FACE_KEYS", "").split(",")):
            kid, _, b64 = item.partition(":")
            keys[kid] = base64.b64decode(b64)
        s = Settings(
            models_dir=Path(os.environ.get("FACE_MODELS_DIR", "models")),
            keys=keys,
            active_key_id=os.environ.get("FACE_ACTIVE_KEY", ""),
            service_token=os.environ.get("FACE_SERVICE_TOKEN", ""),
            redis_url=os.environ.get("REDIS_URL", ""),
            database_url=os.environ.get("DATABASE_URL", ""),
        )
        if not keys or s.active_key_id not in keys or any(len(k) != 32 for k in keys.values()):
            raise RuntimeError("FACE_KEYS/FACE_ACTIVE_KEY missing or not 32-byte keys")
        if len(s.service_token) < 32:
            raise RuntimeError("FACE_SERVICE_TOKEN must be at least 32 characters")
        if not s.redis_url or not s.database_url:
            raise RuntimeError("REDIS_URL and DATABASE_URL are required")
        return s
