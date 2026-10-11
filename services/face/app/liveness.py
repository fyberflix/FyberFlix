"""Challenge-response liveness based on head yaw. Pure logic, no I/O.

Convention: frames must be UN-MIRRORED (as the camera sees them). When the user
turns their head toward THEIR left, the nose moves toward image right => ratio > 0.
This defeats still photos and naive replay of a fixed clip. It does NOT stop a
real-time deepfake/injection attack; add a passive anti-spoof model and
device attestation before relying on it for high-value accounts.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass

import numpy as np

from .config import Settings


@dataclass(frozen=True)
class Challenge:
    id: str
    subject_ref: str
    purpose: str            # "enroll" | "verify"
    steps: tuple[str, ...]  # e.g. ("center","turn_left","center","turn_right")


def new_challenge(subject_ref: str, purpose: str) -> Challenge:
    turns = ["turn_left", "turn_right"]
    if secrets.randbelow(2):
        turns.reverse()
    return Challenge(secrets.token_urlsafe(24), subject_ref, purpose,
                     ("center", turns[0], "center", turns[1]))


def yaw_ratio(landmarks) -> float:
    (rx, _), (lx, _), (nx, _) = landmarks[0], landmarks[1], landmarks[2]
    d = lx - rx
    if d <= 1e-6:
        raise ValueError("degenerate landmarks")
    return (nx - (rx + lx) / 2.0) / d


def label(r: float, s: Settings) -> str | None:
    if abs(r) <= s.center_ratio:
        return "center"
    if r >= s.turn_ratio:
        return "left"
    if r <= -s.turn_ratio:
        return "right"
    return None  # in-between: ignored


_PHASE = {"center": "center", "turn_left": "left", "turn_right": "right"}


def sequence_ok(labels: list[str | None], steps: tuple[str, ...]) -> bool:
    seen: list[str] = []
    for lab in labels:
        if lab is not None and (not seen or seen[-1] != lab):
            seen.append(lab)
    need = [_PHASE[x] for x in steps]
    i = 0
    for lab in seen:
        if i < len(need) and lab == need[i]:
            i += 1
    return i == len(need)


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.dot(a, b))  # inputs are L2-normalised
