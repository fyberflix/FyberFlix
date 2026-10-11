"""Short-lived state: single-use challenges and failed-attempt counters."""
from __future__ import annotations

import json
import threading
import time
from typing import Protocol

from .liveness import Challenge


class State(Protocol):
    def put_challenge(self, c: Challenge, ttl: int) -> None: ...
    def take_challenge(self, challenge_id: str) -> Challenge | None: ...   # atomic, single use
    def failures(self, ref: str) -> int: ...
    def add_failure(self, ref: str, window: int) -> int: ...
    def clear_failures(self, ref: str) -> None: ...


class MemoryState:
    def __init__(self):
        self._lock = threading.Lock()
        self._ch: dict[str, tuple[float, Challenge]] = {}
        self._fail: dict[str, tuple[float, int]] = {}

    def put_challenge(self, c, ttl):
        with self._lock:
            self._ch[c.id] = (time.time() + ttl, c)

    def take_challenge(self, challenge_id):
        with self._lock:
            item = self._ch.pop(challenge_id, None)
        return item[1] if item and item[0] > time.time() else None

    def failures(self, ref):
        with self._lock:
            exp, n = self._fail.get(ref, (0, 0))
            return n if exp > time.time() else 0

    def add_failure(self, ref, window):
        with self._lock:
            exp, n = self._fail.get(ref, (0, 0))
            if exp <= time.time():
                exp, n = time.time() + window, 0
            self._fail[ref] = (exp, n + 1)
            return n + 1

    def clear_failures(self, ref):
        with self._lock:
            self._fail.pop(ref, None)


class RedisState:
    """Shared across replicas. Requires redis>=5 (GETDEL)."""

    def __init__(self, url: str):
        import redis
        self._r = redis.Redis.from_url(url, decode_responses=True)

    def put_challenge(self, c, ttl):
        body = json.dumps({"r": c.subject_ref, "p": c.purpose, "s": list(c.steps)})
        self._r.set(f"face:ch:{c.id}", body, ex=ttl)

    def take_challenge(self, challenge_id):
        raw = self._r.getdel(f"face:ch:{challenge_id}")
        if not raw:
            return None
        d = json.loads(raw)
        return Challenge(challenge_id, d["r"], d["p"], tuple(d["s"]))

    def failures(self, ref):
        return int(self._r.get(f"face:fail:{ref}") or 0)

    def add_failure(self, ref, window):
        k = f"face:fail:{ref}"
        p = self._r.pipeline()
        p.incr(k)
        p.expire(k, window, nx=True)
        return int(p.execute()[0])

    def clear_failures(self, ref):
        self._r.delete(f"face:fail:{ref}")
