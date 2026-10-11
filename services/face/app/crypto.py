"""AES-256-GCM encryption of face templates, with a key ring for rotation."""
from __future__ import annotations

import os

import numpy as np
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DecryptError(Exception):
    pass


class KeyRing:
    def __init__(self, keys: dict[str, bytes], active: str):
        if active not in keys or any(len(k) != 32 for k in keys.values()):
            raise ValueError("invalid key ring")
        self._keys, self.active = keys, active

    def encrypt(self, template: np.ndarray, aad: bytes) -> tuple[str, bytes, bytes]:
        nonce = os.urandom(12)
        ct = AESGCM(self._keys[self.active]).encrypt(nonce, template.astype("<f4").tobytes(), aad)
        return self.active, nonce, ct

    def decrypt(self, key_id: str, nonce: bytes, ct: bytes, aad: bytes) -> np.ndarray:
        key = self._keys.get(key_id)
        if key is None:
            raise DecryptError("unknown key id")
        try:
            raw = AESGCM(key).decrypt(nonce, ct, aad)
        except InvalidTag as e:
            raise DecryptError("template failed integrity check") from e
        return np.frombuffer(raw, dtype="<f4").copy()
