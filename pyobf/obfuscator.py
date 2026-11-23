"""Orchestration for pyobf v0.1alpha: discover, two-pass rename, write."""
from __future__ import annotations

import ast
import fnmatch
import hashlib
import json
import random
import re
from dataclasses import dataclass, field
from pathlib import Path

from .naming import NameGenerator
from .strings import HELPER_NAME, derive_key, helper_source
from .transform import Renamer


class ObfuscateError(Exception):
    pass


@dataclass
class FileResult:
    src: Path
    rel: Path
    dst: Path
    renamed_locals: int = 0
    renamed_top: int = 0
    strings_encrypted: int = 0
    bytes_in: int = 0
    bytes_out: int = 0


@dataclass
class RunResult:
    files: list[FileResult] = field(default_factory=list)
    mapping: dict[str, dict[str, str]] = field(default_factory=dict)
    seed: str = ""
    level: int = 1
    errors: list[str] = field(default_factory=list)

    @property
    def total_in(self) -> int:
        return sum(f.bytes_in for f in self.files)

    @property
    def total_out(self) -> int:
        return sum(f.bytes_out for f in self.files)


def module_name_for(rel: Path) -> str:
    parts = list(rel.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _is_private_top(name: str) -> bool:
    return name.startswith("_") and not (name.startswith("__") and name.endswith("__"))


def collect_top_maps(
    sources: list[tuple[Path, Path, str]], name_gen: NameGenerator
) -> dict[str, dict[str, str]]:
    """First pass: every private top-level def/class in the project."""
    maps: dict[str, dict[str, str]] = {}
    for _src, rel, text in sources:
        mod = module_name_for(rel)
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            raise ObfuscateError(f"{rel}: 语法错误 {exc.msg} (行 {exc.lineno})") from exc
        top: dict[str, str] = {}
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if _is_private_top(stmt.name):
                    scope = f"{mod}:<module>"
                    top[stmt.name] = name_gen.generate(stmt.name, scope)
        if top:
            maps[mod] = top
    return maps


def _insert_helper(tree: ast.Module, helper_name: str, key: bytes) -> bool:
    """Insert the string-decoder after any ``__future__`` imports."""
    if helper_name in {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}:
        return False
    helper_tree = ast.parse(helper_source(helper_name, key))
    helper_def = helper_tree.body[0]
    idx = 0
    for i, stmt in enumerate(tree.body):
        if isinstance(stmt, ast.ImportFrom) and stmt.module == "__future__":
            idx = i + 1
        else:
            break
    tree.body.insert(idx, helper_def)
    return True


def _junk_source(seed: str, module_name: str) -> str:
    digest = hashlib.sha256(f"{seed}\x00{module_name}\x00junk".encode()).hexdigest()
    rng = random.Random(int(digest[:8], 16))
    lines = ["if False:"]
    for i in range(3):
        name = f"_pyobf_junk_{digest[8 + i * 4:12 + i * 4]}"
        lines.append(f"    {name} = {rng.randint(1000, 999999)}")
    return "\n".join(lines) + "\n"


def discover(input_path: Path, exclude: list[str]) -> list[Path]:
    if input_path.is_file():
        return [input_path] if input_path.suffix == ".py" else []
    found: list[Path] = []
    for p in sorted(input_path.rglob("*.py")):
        rel = p.relative_to(input_path)
        if "__pycache__" in rel.parts or ".venv" in rel.parts or "venv" in rel.parts:
            continue
        if any(part.startswith(".") for part in rel.parts):
            continue
        if any(fnmatch.fnmatch(str(rel), pat) or fnmatch.fnmatch(p.name, pat) for pat in exclude):
            continue
        found.append(p)
    return found


def obfuscate_project(
    *,
    input_path: Path,
    output_path: Path,
    seed: str,
    level: int,
    rename_top: bool | None = None,
    rename_args: bool = False,
    encrypt_strings: bool | None = None,
    strip_docstrings: bool = True,
    add_junk: bool | None = None,
    keep_names: set[str] | None = None,
    exclude: list[str] | None = None,
    dry_run: bool = False,
) -> RunResult:
    if level not in (1, 2, 3):
        raise ObfuscateError("level 只能是 1、2、3")
    if rename_top is None:
        rename_top = level >= 2
    if encrypt_strings is None:
        encrypt_strings = level >= 2
    if add_junk is None:
        add_junk = level >= 3

    keep = set(keep_names or set())
    exclude = list(exclude or [])
    files = discover(input_path, exclude)
    if not files:
        raise ObfuscateError(f"在 {input_path} 下没有找到 .py 文件")

    name_gen = NameGenerator(seed)
    key = derive_key(seed)

    # Read all sources first (fail fast on syntax errors / encoding).
    sources: list[tuple[Path, Path, str]] = []
    for src in files:
        rel = src.relative_to(input_path) if input_path.is_dir() else Path(src.name)
        try:
            text = src.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ObfuscateError(f"{rel}: 不是 UTF-8 文本 ({exc})") from exc
        sources.append((src, rel, text))

    top_maps = collect_top_maps(sources, name_gen) if rename_top else {}

    result = RunResult(seed=str(seed), level=level)
    for src, rel, text in sources:
        mod = module_name_for(rel)
        top_map = top_maps.get(mod, {})
        shebang = ""
        body_text = text
        if text.startswith("#!"):
            first, _, rest = text.partition("\n")
            shebang = first + "\n"
            body_text = rest
        try:
            tree = ast.parse(body_text)
        except SyntaxError as exc:
            raise ObfuscateError(f"{rel}: 语法错误 {exc.msg} (行 {exc.lineno})") from exc

        renamer = Renamer(
            seed=str(seed),
            name_gen=name_gen,
            module_name=mod,
            top_map=top_map,
            global_top_maps=top_maps,
            rename_top=rename_top,
            rename_args=rename_args,
            encrypt_strings=encrypt_strings,
            strip_docstrings=strip_docstrings,
            keep_names=keep,
            key=key,
        )
        new_tree = renamer.transform(tree)

        needs_helper = renamer.stats["strings_encrypted"] > 0
        if needs_helper:
            _insert_helper(new_tree, HELPER_NAME, key)
        if add_junk:
            junk_tree = ast.parse(_junk_source(str(seed), mod))
            new_tree.body.append(junk_tree.body[0])

        ast.fix_missing_locations(new_tree)
        try:
            out_text = ast.unparse(new_tree)
        except Exception as exc:  # pragma: no cover - unparse rarely fails
            raise ObfuscateError(f"{rel}: 生成代码失败 ({exc})") from exc
        if shebang:
            out_text = shebang + out_text + "\n"
        else:
            out_text = out_text + "\n"

        dst = output_path / rel if input_path.is_dir() else output_path
        # single-file input: output_path is a file, or a dir -> file inside
        if input_path.is_file() and output_path.is_dir():
            dst = output_path / src.name
        fr = FileResult(
            src=src,
            rel=rel,
            dst=dst,
            renamed_locals=renamer.stats["renamed_locals"],
            renamed_top=renamer.stats["renamed_top"],
            strings_encrypted=renamer.stats["strings_encrypted"],
            bytes_in=len(text.encode("utf-8")),
            bytes_out=len(out_text.encode("utf-8")),
        )
        result.files.append(fr)
        if renamer.mapping:
            result.mapping[str(rel)] = dict(renamer.mapping)
        if not dry_run:
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(out_text, encoding="utf-8")
    return result


def mapping_payload(result: RunResult) -> dict:
    return {
        "tool": "pyobf",
        "version": "0.1.0-alpha",
        "seed": result.seed,
        "level": result.level,
        "warning": "此映射文件可用于调试还原，发布时不要随混淆产物一起分发。",
        "files": result.mapping,
    }


def write_mapping(result: RunResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(mapping_payload(result), ensure_ascii=False, indent=2), encoding="utf-8")
