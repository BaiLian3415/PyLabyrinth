"""String encryption for pyobf v0.1alpha: XOR + base64, stdlib only.

The key is derived from the seed, so the same seed decrypts the same
output. The runtime helper is injected *after* AST transformation, so
its own locals are never renamed.
"""
from __future__ import annotations

import base64
import hashlib

HELPER_NAME = "_pyobf_s"


def derive_key(seed: str, length: int = 16) -> bytes:
    return hashlib.sha256(f"pyobf-str\x00{seed}".encode("utf-8")).digest()[:length]


def encrypt_str(text: str, key: bytes) -> str:
    raw = text.encode("utf-8")
    xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    return base64.b64encode(xored).decode("ascii")


def decrypt_str(encoded: str, key: bytes) -> str:
    raw = base64.b64decode(encoded.encode("ascii"))
    plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    return plain.decode("utf-8")


def helper_source(helper_name: str, key: bytes) -> str:
    """Source of the runtime decoder, to be parsed and inserted as AST."""
    key_hex = key.hex()
    return (
        f"def {helper_name}(_s):\n"
        f"    import base64 as _b64\n"
        f"    _k = bytes.fromhex(\"{key_hex}\")\n"
        f"    _b = _b64.b64decode(_s.encode(\"ascii\"))\n"
        f"    return bytes(_c ^ _k[_i % len(_k)] for _i, _c in enumerate(_b)).decode(\"utf-8\")\n"
    )
