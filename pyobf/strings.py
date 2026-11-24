"""String encryption for pyobf v0.1alpha.2: per-string salted XOR + base64.

Alpha.1 weakness, fixed here:
- one global XOR key, stored as a plain hex literal in a helper always
  called ``_pyobf_s``. Find the key once, decrypt every string in the
  file; grep for the helper name and the job is half done.

Alpha.2:
- no global XOR key. Each string gets its own 4-byte salt (deterministic
  from seed + module + occurrence index, so output is reproducible).
  Its key is ``SHA256(master + salt)``; the payload is
  ``base64(salt + xor(utf8, key))``. Extracting one string's key tells
  an attacker nothing about the next string.
- the master is derived from the seed (``SHA256("pyobf-master" + seed)``)
  and is embedded in the helper only as a ``bytes([...])`` integer list,
  never as a hex string, and never as the seed itself.
- the helper name is different in every file (deterministic from
  seed + module), so there is no fixed marker to grep for.
- the helper is injected *after* AST transformation, so its own locals
  are never renamed.
"""
from __future__ import annotations

import base64
import hashlib

# Kept for backwards compatibility with callers that only need a name
# that is guaranteed not to collide with user code in the alpha.1 sense.
# Alpha.2 code should use helper_name_for(seed, module) instead.
HELPER_NAME = "_pyobf_s"


def derive_master(seed: str) -> bytes:
    return hashlib.sha256(f"pyobf-master\x00{seed}".encode("utf-8")).digest()


def derive_key(seed: str, length: int = 16) -> bytes:
    """Alpha.1 helper kept for tests/tools: master truncated."""
    return derive_master(seed)[:length]


def make_salt(seed: str, module: str, index: int) -> bytes:
    return hashlib.sha256(f"{seed}\x00{module}\x00str\x00{index}".encode("utf-8")).digest()[:4]


def helper_name_for(seed: str, module: str) -> str:
    digest = hashlib.sha256(f"{seed}\x00{module}\x00helper".encode("utf-8")).hexdigest()
    return "_" + digest[:10]


def bytes_helper_name_for(seed: str, module: str) -> str:
    digest = hashlib.sha256(f"{seed}\x00{module}\x00bytes-helper".encode("utf-8")).hexdigest()
    return "_" + digest[:10]


def _per_string_key(master: bytes, salt: bytes) -> bytes:
    return hashlib.sha256(master + salt).digest()


def encrypt_str(text: str, master: bytes, salt: bytes | None = None) -> str:
    """Encrypt with an explicit salt (tests / single-string use).

    If no salt is given, a zero salt is used; production code in
    transform.py always passes a per-string salt from make_salt().
    """
    if salt is None:
        salt = b"\x00\x00\x00\x00"
    key = _per_string_key(master, salt)
    raw = text.encode("utf-8")
    xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    return base64.b64encode(salt + xored).decode("ascii")


def encrypt_str_indexed(text: str, master: bytes, seed: str, module: str, index: int) -> str:
    return encrypt_str(text, master, make_salt(seed, module, index))


def decrypt_str(encoded: str, master: bytes) -> str:
    raw = base64.b64decode(encoded.encode("ascii"))
    salt, data = raw[:4], raw[4:]
    key = _per_string_key(master, salt)
    plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return plain.decode("utf-8")


def encrypt_bytes(data: bytes, master: bytes, salt: bytes | None = None) -> str:
    if salt is None:
        salt = b"\x00\x00\x00\x00"
    key = _per_string_key(master, salt)
    xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return base64.b64encode(salt + xored).decode("ascii")


def encrypt_bytes_indexed(data: bytes, master: bytes, seed: str, module: str, index: int) -> str:
    return encrypt_bytes(data, master, make_salt(seed, module, index))


def decrypt_bytes(encoded: str, master: bytes) -> bytes:
    raw = base64.b64decode(encoded.encode("ascii"))
    salt, data = raw[:4], raw[4:]
    key = _per_string_key(master, salt)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def helper_source(helper_name: str, master: bytes) -> str:
    """Source of the runtime decoder, to be parsed and inserted as AST."""
    master_list = ", ".join(str(b) for b in master)
    return (
        f"def {helper_name}(_s):\n"
        f"    import base64 as _b64\n"
        f"    import hashlib as _hl\n"
        f"    _m = bytes([{master_list}])\n"
        f"    _r = _b64.b64decode(_s.encode(\"ascii\"))\n"
        f"    _k = _hl.sha256(_m + _r[:4]).digest()\n"
        f"    return bytes(_c ^ _k[_i % len(_k)] for _i, _c in enumerate(_r[4:])).decode(\"utf-8\")\n"
    )


def helper_source_bytes(helper_name: str, master: bytes) -> str:
    """Same decoder, but returns bytes instead of a str (for b\"...\" literals)."""
    master_list = ", ".join(str(b) for b in master)
    return (
        f"def {helper_name}(_s):\n"
        f"    import base64 as _b64\n"
        f"    import hashlib as _hl\n"
        f"    _m = bytes([{master_list}])\n"
        f"    _r = _b64.b64decode(_s.encode(\"ascii\"))\n"
        f"    _k = _hl.sha256(_m + _r[:4]).digest()\n"
        f"    return bytes(_c ^ _k[_i % len(_k)] for _i, _c in enumerate(_r[4:]))\n"
    )
