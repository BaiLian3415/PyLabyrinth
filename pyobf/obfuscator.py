"""Orchestration for pyobf v0.1alpha.3: discover, two-pass rename, write."""
from __future__ import annotations

import ast
import fnmatch
import hashlib
import json
import random
from dataclasses import dataclass, field
from pathlib import Path

from .naming import NameGenerator
from .strings import bytes_helper_name_for, derive_master, helper_name_for, helper_source, helper_source_bytes
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
    ints_obfuscated: int = 0
    bytes_encrypted: int = 0
    attrs_renamed: int = 0
    shuffled_defs: int = 0
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


def _private_targets(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        out: list[str] = []
        for elt in target.elts:
            out.extend(_private_targets(elt))
        return out
    return []


def collect_top_maps(
    sources: list[tuple[Path, Path, str]], name_gen: NameGenerator
) -> dict[str, dict[str, str]]:
    """First pass: every private top-level def/class/variable in the project.

    Alpha.2 adds private module-level variables (``_SECRET = ...``) to the
    map that alpha.1 only built for def/class names. Cross-file imports
    and ``mod._SECRET`` attribute access are rewritten by the same
    machinery as for private functions.
    """
    maps: dict[str, dict[str, str]] = {}
    for _src, rel, text in sources:
        mod = module_name_for(rel)
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            raise ObfuscateError(f"{rel}: 语法错误 {exc.msg} (行 {exc.lineno})") from exc
        top: dict[str, str] = {}
        scope = f"{mod}:<module>"

        def _add(name: str) -> None:
            if _is_private_top(name) and name not in top:
                top[name] = name_gen.generate(name, scope)

        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                _add(stmt.name)
            elif isinstance(stmt, ast.Assign):
                for tgt in stmt.targets:
                    for name in _private_targets(tgt):
                        _add(name)
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                _add(stmt.target.id)
        if top:
            maps[mod] = top
    return maps


def _insert_helper(tree: ast.Module, helper_name: str, source: str, mapping_values: set[str]) -> str:
    """Insert a decoder (str or bytes) after any ``__future__`` imports.

    Returns the helper name actually used. If the deterministic name
    collides with a renamed identifier in this file (vanishingly rare,
    but checked), the call sites are rewritten to a suffixed name.
    ``source`` must be the helper source for ``actual``; it is
    regenerated here when a suffix is applied.
    """
    actual = helper_name
    suffix = 1
    existing_defs = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    while actual in mapping_values or actual in existing_defs:
        actual = f"{helper_name}_{suffix}"
        suffix += 1
    if actual != helper_name:
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == helper_name:
                node.id = actual
        # source was built for the unsuffixed name; rebuild it
        source = source.replace(f"def {helper_name}(", f"def {actual}(", 1)
    helper_tree = ast.parse(source)
    helper_def = helper_tree.body[0]
    idx = 0
    for i, stmt in enumerate(tree.body):
        if isinstance(stmt, ast.ImportFrom) and stmt.module == "__future__":
            idx = i + 1
        else:
            break
    tree.body.insert(idx, helper_def)
    return actual


def _def_time_names(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> set[str]:
    """Names a def/class references at definition time (decorators,
    defaults, bases, annotations). Body references do not count: the
    body runs later, after every def is defined."""
    names: set[str] = set()
    parts: list[ast.AST] = list(node.decorator_list)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        parts.extend(node.args.defaults)
        parts.extend(d for d in node.args.kw_defaults if d is not None)
        if node.returns is not None:
            parts.append(node.returns)
        for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            if arg.annotation is not None:
                parts.append(arg.annotation)
    else:
        parts.extend(node.bases)
        parts.extend(kw.value for kw in node.keywords)
    for part in parts:
        for sub in ast.walk(part):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                names.add(sub.id)
    return names


def _shuffle_top_defs(tree: ast.Module, seed: str, module: str) -> int:
    """Shuffle independent top-level defs/class (level 3 only).

    Only defs whose definition-time dependencies do not reference any
    other top-level name are moved, and only among the slots of other
    movable defs. If any top-level statement between/before the defs
    references a top-level def (other than a trailing ``if __name__``
    guard, which runs after all defs), shuffling is skipped for the
    whole file. Returns how many defs changed position.
    """
    body = tree.body
    def_idx = [i for i, s in enumerate(body) if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    if len(def_idx) < 2:
        return 0
    top_names = {body[i].name for i in def_idx}
    last_def = def_idx[-1]
    for i, stmt in enumerate(body):
        if i in def_idx or i > last_def:
            continue
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            continue
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Name) and sub.id in top_names:
                return 0
    movable = [i for i in def_idx if not (_def_time_names(body[i]) & top_names)]
    if len(movable) < 2:
        return 0
    rng = random.Random(int(hashlib.sha256(f"{seed}\x00{module}\x00shuffle".encode()).hexdigest()[:8], 16))
    defs = [body[i] for i in movable]
    shuffled = defs[:]
    rng.shuffle(shuffled)
    if shuffled == defs:
        return 0
    moved = 0
    for slot, node in zip(movable, shuffled):
        if body[slot] is not node:
            moved += 1
        body[slot] = node
    return moved


def _junk_source(seed: str, module_name: str) -> str:
    """Dead code for level 3: opaque predicate + an unused function.

    Alpha.1 used a literal ``if False:``. Alpha.2 uses an opaque
    predicate whose falsity requires computing ``(a * b) % 7`` (the
    embedded target is chosen so the condition is False by construction)
    and adds one never-called function with a realistic-looking body.
    Neither ever executes.
    """
    digest = hashlib.sha256(f"{seed}\x00{module_name}\x00junk".encode()).hexdigest()
    rng = random.Random(int(digest[:8], 16))
    a, b = rng.randint(10, 99), rng.randint(10, 99)
    target = ((a * b) % 7 + 1) % 7  # condition below is False by construction
    junk_fn = "_" + digest[12:22]
    lines = [
        f"def {junk_fn}(_a, _b):",
        "    _t = 0",
        "    for _i in range(_a):",
        "        _t += _i * _b",
        "    return _t",
        "",
        f"if {a} * {b} % 7 == {target}:",
    ]
    for i in range(3):
        name = f"_{digest[8 + i * 4:12 + i * 4]}"
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
    obfuscate_ints: bool | None = None,
    rename_attrs: bool | None = None,
    shuffle_top: bool | None = None,
) -> RunResult:
    if level not in (1, 2, 3):
        raise ObfuscateError("level 只能是 1、2、3")
    if rename_top is None:
        rename_top = level >= 2
    if encrypt_strings is None:
        encrypt_strings = level >= 2
    if add_junk is None:
        add_junk = level >= 3
    if obfuscate_ints is None:
        obfuscate_ints = level >= 2
    if rename_attrs is None:
        rename_attrs = level >= 2
    if shuffle_top is None:
        shuffle_top = level >= 3

    keep = set(keep_names or set())
    exclude = list(exclude or [])
    files = discover(input_path, exclude)
    if not files:
        raise ObfuscateError(f"在 {input_path} 下没有找到 .py 文件")

    name_gen = NameGenerator(seed)
    master = derive_master(seed)

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

        helper_name = helper_name_for(str(seed), mod)
        bytes_helper_name = bytes_helper_name_for(str(seed), mod)
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
            master=master,
            helper_name=helper_name,
            bytes_helper_name=bytes_helper_name,
            obfuscate_ints=obfuscate_ints,
            rename_attrs=rename_attrs,
        )
        new_tree = renamer.transform(tree)

        shuffled = _shuffle_top_defs(new_tree, str(seed), mod) if shuffle_top else 0
        if renamer.stats["strings_encrypted"] > 0:
            _insert_helper(new_tree, helper_name, helper_source(helper_name, master), set(renamer.mapping.values()))
        if renamer.stats["bytes_encrypted"] > 0:
            _insert_helper(new_tree, bytes_helper_name, helper_source_bytes(bytes_helper_name, master), set(renamer.mapping.values()))
        if add_junk:
            junk_tree = ast.parse(_junk_source(str(seed), mod))
            # junk source is now several statements (unused function +
            # opaque dead branch); append all of them, not just [0]
            new_tree.body.extend(junk_tree.body)

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
            ints_obfuscated=renamer.stats["ints_obfuscated"],
            bytes_encrypted=renamer.stats["bytes_encrypted"],
            attrs_renamed=renamer.stats["attrs_renamed"],
            shuffled_defs=shuffled,
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
        "version": "0.1.0-alpha.3",
        "seed": result.seed,
        "level": result.level,
        "warning": "此映射文件可用于调试还原，发布时不要随混淆产物一起分发。",
        "files": result.mapping,
    }


def write_mapping(result: RunResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(mapping_payload(result), ensure_ascii=False, indent=2), encoding="utf-8")
