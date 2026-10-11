import os
import unittest

import numpy as np

from app.config import Settings
from app.crypto import DecryptError, KeyRing
from app.liveness import label, sequence_ok, yaw_ratio
from app.service import FaceService
from app.state import MemoryState
from app.store import MemoryStore
from app.vision import FaceObs, FrameRejected, unit

S = Settings()
REF = "6f1d5f0e-1c1a-4c1c-9a53-0d6f3a2f9b11"


def person_vec(name: str) -> np.ndarray:
    rng = np.random.default_rng(sum(map(ord, name)))
    return unit(rng.normal(size=128))


class FakeVision:
    """Frame bytes look like b'<person>|<yaw ratio>'; b'bad' simulates a rejected frame."""
    model_id = "fake-v1"

    def analyze(self, raw: bytes) -> FaceObs:
        if raw == b"bad":
            raise FrameRejected("blurry")
        who, r = raw.decode().split("|")
        r = float(r)
        noise = np.random.default_rng(len(raw) + abs(int(r * 1000)) + 7).normal(scale=0.02, size=128)
        emb = unit(person_vec(who) + noise)
        nose_x = 60 + r * 40
        return FaceObs(((40, 50), (80, 50), (nose_x, 70), (45, 90), (75, 90)), emb, 0.99)


def frames(person: str, pattern: list[float]) -> list[bytes]:
    return [f"{person}|{r}".encode() for r in pattern]


def make() -> FaceService:
    keys = KeyRing({"k1": os.urandom(32)}, "k1")
    return FaceService(S, FakeVision(), MemoryStore(), MemoryState(), keys)


def chall(svc: FaceService, purpose: str):
    return svc.create_challenge(REF, purpose)


def good_for(c, person="alice") -> list[bytes]:
    # frames that follow the challenge order, whichever turn comes first
    first = 0.3 if c.steps[1] == "turn_left" else -0.3
    second = -first
    pat = [0, 0.02, first, first * 1.1, 0.03, 0.0, second, second * 1.1, 0.02, 0.0]
    return frames(person, pat)


class LivenessTests(unittest.TestCase):
    def test_labels(self):
        self.assertEqual(label(0.0, S), "center")
        self.assertEqual(label(0.3, S), "left")
        self.assertEqual(label(-0.3, S), "right")
        self.assertIsNone(label(0.17, S))

    def test_yaw_sign(self):
        lm = ((40, 50), (80, 50), (72, 70), (0, 0), (0, 0))
        self.assertGreater(yaw_ratio(lm), 0)

    def test_sequence(self):
        steps = ("center", "turn_left", "center", "turn_right")
        ok = ["center", "left", "left", "center", None, "right", "center"]
        self.assertTrue(sequence_ok(ok, steps))
        self.assertFalse(sequence_ok(["center"] * 8, steps))                         # static photo
        self.assertFalse(sequence_ok(["center", "right", "center", "left"], steps))  # wrong order


class CryptoTests(unittest.TestCase):
    def test_roundtrip_aad_and_rotation(self):
        k1, k2 = os.urandom(32), os.urandom(32)
        v = unit(np.random.default_rng(1).normal(size=128))
        old = KeyRing({"k1": k1}, "k1")
        kid, n, ct = old.encrypt(v, b"ref|m")
        rotated = KeyRing({"k1": k1, "k2": k2}, "k2")
        np.testing.assert_allclose(rotated.decrypt(kid, n, ct, b"ref|m"), v, rtol=1e-6)
        with self.assertRaises(DecryptError):
            rotated.decrypt(kid, n, ct, b"other|m")          # row swapped to another subject
        with self.assertRaises(DecryptError):
            rotated.decrypt(kid, n, ct[:-1] + bytes([ct[-1] ^ 1]), b"ref|m")


class ServiceTests(unittest.TestCase):
    def enroll(self, svc, person="alice"):
        c = chall(svc, "enroll")
        return svc.enroll(REF, c.id, good_for(c, person))

    def test_enroll_then_verify_same_person(self):
        svc = make()
        self.assertTrue(self.enroll(svc).ok)
        c = chall(svc, "verify")
        r = svc.verify(REF, c.id, good_for(c))
        self.assertTrue(r.ok, r)

    def test_different_person_rejected(self):
        svc = make()
        self.enroll(svc)
        c = chall(svc, "verify")
        r = svc.verify(REF, c.id, good_for(c, "mallory"))
        self.assertEqual((r.ok, r.reason), (False, "no_match"))

    def test_static_photo_fails_liveness(self):
        svc = make()
        c = chall(svc, "enroll")
        r = svc.enroll(REF, c.id, frames("alice", [0.0] * 10))
        self.assertEqual(r.reason, "liveness_failed")

    def test_swap_person_mid_session_fails(self):
        svc = make()
        c = chall(svc, "enroll")
        fr = good_for(c)
        fr[5:] = [f.replace(b"alice", b"mallory") for f in fr[5:]]
        self.assertEqual(svc.enroll(REF, c.id, fr).reason, "liveness_failed")

    def test_challenge_single_use_and_bound(self):
        svc = make()
        c = chall(svc, "enroll")
        fr = good_for(c)
        self.assertTrue(svc.enroll(REF, c.id, fr).ok)
        self.assertEqual(svc.enroll("0f1d5f0e-1c1a-4c1c-9a53-0d6f3a2f9b99", c.id, fr).reason, "challenge_invalid")
        c2 = chall(svc, "verify")
        self.assertEqual(svc.enroll(REF, c2.id, fr).reason, "already_enrolled")

    def test_no_overwrite_of_existing_template(self):
        svc = make()
        self.assertTrue(self.enroll(svc).ok)
        self.assertEqual(self.enroll(svc, "mallory").reason, "already_enrolled")

    def test_lockout_after_repeated_failures_then_delete(self):
        svc = make()
        self.enroll(svc)
        for _ in range(S.max_failures):
            c = chall(svc, "verify")
            svc.verify(REF, c.id, good_for(c, "mallory"))
        c = chall(svc, "verify")
        self.assertEqual(svc.verify(REF, c.id, good_for(c)).reason, "locked")
        self.assertTrue(svc.delete(REF))
        self.assertEqual(svc.verify(REF, c.id, good_for(c)).reason, "not_enrolled")

    def test_bad_frames_are_skipped_not_fatal(self):
        svc = make()
        c = chall(svc, "enroll")
        fr = good_for(c)
        fr.insert(3, b"bad")
        self.assertTrue(svc.enroll(REF, c.id, fr).ok)


if __name__ == "__main__":
    unittest.main()
