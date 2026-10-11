"""Face enrol / verify orchestration."""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .config import Settings
from .crypto import DecryptError, KeyRing
from .liveness import Challenge, cosine, label, new_challenge, sequence_ok, yaw_ratio
from .state import State
from .store import Record, TemplateStore
from .vision import FrameRejected, Vision, unit


@dataclass(frozen=True)
class Result:
    ok: bool
    reason: str | None = None   # machine code; auth-service maps it to user text
    score: float | None = None  # internal only: never expose to end users


class FaceService:
    def __init__(self, s: Settings, vision: Vision, store: TemplateStore, state: State, keys: KeyRing):
        self.s, self.vision, self.store, self.state, self.keys = s, vision, store, state, keys

    @staticmethod
    def _aad(ref: str, model_id: str) -> bytes:
        return f"{ref}|{model_id}".encode()

    def create_challenge(self, subject_ref: str, purpose: str) -> Challenge:
        c = new_challenge(subject_ref, purpose)
        self.state.put_challenge(c, self.s.challenge_ttl)
        return c

    # ---- shared: challenge + liveness -> face template from this session ----
    def _session_template(self, ref: str, purpose: str, challenge_id: str, frames: list[bytes]):
        s = self.s
        ch = self.state.take_challenge(challenge_id)       # single use, even if we fail below
        if ch is None or ch.subject_ref != ref or ch.purpose != purpose:
            return None, Result(False, "challenge_invalid")
        if not (s.min_frames <= len(frames) <= s.max_frames):
            return None, Result(False, "bad_frame_count")
        obs = []
        for raw in frames:
            try:
                obs.append(self.vision.analyze(raw))
            except FrameRejected:
                continue                                   # skip unusable frames (blur, no face, ...)
        if len(obs) < s.min_frames:
            return None, Result(False, "poor_quality")
        try:
            labels = [label(yaw_ratio(o.landmarks), s) for o in obs]
        except ValueError:
            return None, Result(False, "poor_quality")
        for a, b in zip(obs, obs[1:]):
            if cosine(a.embedding, b.embedding) < s.chain_threshold:
                return None, Result(False, "liveness_failed")   # identity changed mid-session
        if not sequence_ok(labels, ch.steps):
            return None, Result(False, "liveness_failed")
        centers = [o.embedding for o, lab in zip(obs, labels) if lab == "center"]
        if len(centers) < s.min_center_frames:
            return None, Result(False, "poor_quality")
        return unit(np.mean(centers, axis=0)), None

    def enroll(self, ref: str, challenge_id: str, frames: list[bytes]) -> Result:
        if self.store.get(ref) is not None:
            return Result(False, "already_enrolled")
        tpl, err = self._session_template(ref, "enroll", challenge_id, frames)
        if err:
            return err
        kid, nonce, ct = self.keys.encrypt(tpl, self._aad(ref, self.vision.model_id))
        if not self.store.put(ref, Record(kid, nonce, ct, self.vision.model_id)):
            return Result(False, "already_enrolled")
        return Result(True)

    def verify(self, ref: str, challenge_id: str, frames: list[bytes]) -> Result:
        s = self.s
        if self.state.failures(ref) >= s.max_failures:
            return Result(False, "locked")
        rec = self.store.get(ref)
        if rec is None:
            return Result(False, "not_enrolled")
        if rec.model_id != self.vision.model_id:
            return Result(False, "model_mismatch")
        tpl, err = self._session_template(ref, "verify", challenge_id, frames)
        if err:
            if err.reason == "liveness_failed":
                self.state.add_failure(ref, s.failure_window)
            return err
        try:
            enrolled = self.keys.decrypt(rec.key_id, rec.nonce, rec.ciphertext, self._aad(ref, rec.model_id))
        except DecryptError:
            return Result(False, "template_corrupt")
        score = cosine(unit(enrolled), tpl)
        if score >= s.match_threshold:
            self.state.clear_failures(ref)
            return Result(True, None, score)
        self.state.add_failure(ref, s.failure_window)
        return Result(False, "no_match", score)

    def delete(self, ref: str) -> bool:
        self.state.clear_failures(ref)
        return self.store.delete(ref)
