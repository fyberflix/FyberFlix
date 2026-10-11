"""Face detection + embedding. OpenCV YuNet (detector) and SFace (recognizer)."""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Protocol

import cv2
import numpy as np

from .config import Settings


class FrameRejected(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class FaceObs:
    landmarks: tuple[tuple[float, float], ...]  # right eye, left eye, nose, right mouth, left mouth (image coords)
    embedding: np.ndarray                        # L2-normalised
    score: float


class Vision(Protocol):
    model_id: str

    def analyze(self, jpeg: bytes) -> FaceObs: ...


def unit(v: np.ndarray) -> np.ndarray:
    v = np.asarray(v, dtype=np.float32).ravel()
    n = float(np.linalg.norm(v))
    return v / n if n > 0 else v


class OpenCVVision:
    model_id = "yunet-2023mar+sface-2021dec"

    def __init__(self, s: Settings):
        self._s = s
        det = str(s.models_dir / s.detector_file)
        rec = str(s.models_dir / s.recognizer_file)
        self._det = cv2.FaceDetectorYN.create(det, "", (320, 320), s.min_det_score, 0.3, 5000)
        self._rec = cv2.FaceRecognizerSF.create(rec, "")
        self._lock = threading.Lock()  # OpenCV detector holds per-call state

    def analyze(self, jpeg: bytes) -> FaceObs:
        s = self._s
        img = cv2.imdecode(np.frombuffer(jpeg, np.uint8), cv2.IMREAD_COLOR)
        if img is None:
            raise FrameRejected("decode_error")
        h, w = img.shape[:2]
        if max(h, w) > s.max_image_side:
            k = s.max_image_side / max(h, w)
            img = cv2.resize(img, (int(w * k), int(h * k)), interpolation=cv2.INTER_AREA)
            h, w = img.shape[:2]
        with self._lock:
            self._det.setInputSize((w, h))
            _, faces = self._det.detect(img)
            if faces is None or len(faces) == 0:
                raise FrameRejected("no_face")
            if len(faces) > 1:
                raise FrameRejected("multiple_faces")
            f = faces[0]
            x, y, bw, bh = (float(v) for v in f[:4])
            if min(bw, bh) < s.min_face_px:
                raise FrameRejected("too_small")
            crop = img[max(int(y), 0):int(y + bh), max(int(x), 0):int(x + bw)]
            if crop.size == 0:
                raise FrameRejected("no_face")
            gray = cv2.cvtColor(cv2.resize(crop, (160, 160)), cv2.COLOR_BGR2GRAY)
            if cv2.Laplacian(gray, cv2.CV_64F).var() < s.min_sharpness:
                raise FrameRejected("blurry")
            feat = self._rec.feature(self._rec.alignCrop(img, f))
        pts = tuple((float(f[4 + 2 * i]), float(f[5 + 2 * i])) for i in range(5))
        return FaceObs(landmarks=pts, embedding=unit(feat), score=float(f[14]))
