"""Deterministic identifier generation for pyobf v0.1alpha.

Only stdlib. Names are derived from ``seed + scope + original`` so the
same input + seed always produces the same output, which is what makes
the mapping file reproducible and cross-file renames consistent.
"""
from __future__ import annotations

import hashlib
import keyword

_BUILTINS = set(dir(__builtins__)) if isinstance(__builtins__, dict) else set(dir(__builtins__))
# dir(__builtins__) differs between module/dict; be explicit about the
# names we must never emit as an obfuscated identifier.
_RESERVED = set(keyword.kwlist) | {
    "True", "False", "None",
    "abs", "all", "any", "ascii", "bin", "bool", "breakpoint", "bytearray",
    "bytes", "callable", "chr", "classmethod", "compile", "complex",
    "copyright", "credits", "delattr", "dict", "dir", "divmod", "enumerate",
    "eval", "exec", "exit", "filter", "float", "format", "frozenset",
    "getattr", "globals", "hasattr", "hash", "help", "hex", "id", "input",
    "int", "isinstance", "issubclass", "iter", "len", "license", "list",
    "locals", "map", "max", "memoryview", "min", "next", "object", "oct",
    "open", "ord", "pow", "print", "property", "quit", "range", "repr",
    "reversed", "round", "set", "setattr", "slice", "sorted", "staticmethod",
    "str", "sum", "super", "tuple", "type", "vars", "zip", "__import__",
    "__build_class__", "__debug__", "__doc__", "__loader__", "__name__",
    "__package__", "__spec__",
}


def _hash_name(seed: str, scope: str, original: str, length: int = 8) -> str:
    digest = hashlib.sha256(f"{seed}\x00{scope}\x00{original}".encode("utf-8")).hexdigest()
    return "_o" + digest[:length]


class NameGenerator:
    """Generate collision-free obfuscated names, deterministically."""

    def __init__(self, seed: str):
        self.seed = str(seed)
        # (scope, obfuscated) already handed out, to avoid collisions
        self._used: set[tuple[str, str]] = set()
        # (scope, original) -> obfuscated, for stable reuse in one run
        self._cache: dict[tuple[str, str], str] = {}

    def generate(self, original: str, scope: str) -> str:
        key = (scope, original)
        if key in self._cache:
            return self._cache[key]
        base = _hash_name(self.seed, scope, original)
        candidate = base
        suffix = 1
        while candidate in _RESERVED or (scope, candidate) in self._used:
            candidate = f"{base}_{suffix}"
            suffix += 1
        self._cache[key] = candidate
        self._used.add((scope, candidate))
        return candidate

    def is_reserved(self, name: str) -> bool:
        return name in _RESERVED or keyword.iskeyword(name)
