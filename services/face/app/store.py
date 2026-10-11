"""Encrypted template storage."""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Record:
    key_id: str
    nonce: bytes
    ciphertext: bytes
    model_id: str


class TemplateStore(Protocol):
    def put(self, ref: str, rec: Record) -> bool: ...   # False if already enrolled (never overwrite)
    def get(self, ref: str) -> Record | None: ...
    def delete(self, ref: str) -> bool: ...


class MemoryStore:
    def __init__(self):
        self._lock, self._d = threading.Lock(), {}

    def put(self, ref, rec):
        with self._lock:
            if ref in self._d:
                return False
            self._d[ref] = rec
            return True

    def get(self, ref):
        return self._d.get(ref)

    def delete(self, ref):
        with self._lock:
            return self._d.pop(ref, None) is not None


class PostgresStore:
    def __init__(self, dsn: str):
        from psycopg_pool import ConnectionPool
        self._pool = ConnectionPool(dsn, min_size=1, max_size=10, open=True)

    def put(self, ref, rec):
        with self._pool.connection() as c:
            cur = c.execute(
                "INSERT INTO face_templates (subject_ref,key_id,nonce,ciphertext,model_id) "
                "VALUES (%s,%s,%s,%s,%s) ON CONFLICT (subject_ref) DO NOTHING",
                (ref, rec.key_id, rec.nonce, rec.ciphertext, rec.model_id))
            return cur.rowcount == 1

    def get(self, ref):
        with self._pool.connection() as c:
            row = c.execute("SELECT key_id,nonce,ciphertext,model_id FROM face_templates "
                            "WHERE subject_ref=%s", (ref,)).fetchone()
        return Record(row[0], bytes(row[1]), bytes(row[2]), row[3]) if row else None

    def delete(self, ref):
        with self._pool.connection() as c:
            return c.execute("DELETE FROM face_templates WHERE subject_ref=%s", (ref,)).rowcount == 1
