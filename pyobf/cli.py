"""CLI for pyobf v0.1alpha.3.

Usage (both work):
    python -m pyobf -i src -o dist            # from the project root
    python pyobf/cli.py -i src -o dist        # from the project root
    python cli.py -i src -o dist              # from inside the pyobf/ folder
"""
from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

if __package__ in (None, ""):
    # Executed as a plain script (e.g. `python pyobf/cli.py` or
    # `cd pyobf && python cli.py`): there is no parent package, so
    # relative imports would fail with "attempted relative import with
    # no known parent package". Put the project root on sys.path and
    # import as absolute package imports instead.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from pyobf import __version__
    from pyobf.obfuscator import ObfuscateError, obfuscate_project, write_mapping
else:
    from . import __version__
    from .obfuscator import ObfuscateError, obfuscate_project, write_mapping


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pyobf",
        description="pyobf v0.1alpha.3 — 纯标准库的 Python 代码混淆器（AST 方式，不用正则改名）。",
    )
    p.add_argument("--version", action="version", version=f"pyobf {__version__}")
    p.add_argument("-i", "--input", required=True, help="输入：单个 .py 文件或目录")
    p.add_argument("-o", "--output", required=False, help="输出：文件或目录。默认：输入名 + _obf")
    p.add_argument("--seed", default=None, help="随机种子（字符串/数字）。不给则随机生成并打印出来，方便复现")
    p.add_argument("--level", type=int, choices=[1, 2, 3], default=1,
                   help="强度：1=仅局部变量重命名+去注释；2=+私有顶层/私有属性改名+逐串加盐字符串与 bytes 加密+不可折叠整数混淆；3=+不透明死代码+顶层函数乱序。默认 1")
    p.add_argument("--rename-top", dest="rename_top", action="store_true", default=None, help="重命名私有顶层 def/class/变量（level>=2 默认开启）")
    p.add_argument("--no-rename-top", dest="rename_top", action="store_false", help="不重命名顶层 def/class")
    p.add_argument("--strings", dest="strings", action="store_true", default=None, help="加密字符串常量（level>=2 默认开启）")
    p.add_argument("--no-strings", dest="strings", action="store_false", help="不加密字符串")
    p.add_argument("--ints", dest="ints", action="store_true", default=None, help="混淆整数常量（level>=2 默认开启）")
    p.add_argument("--no-ints", dest="ints", action="store_false", help="不混淆整数")
    p.add_argument("--attrs", dest="attrs", action="store_true", default=None, help="重命名私有属性 self._x / 私有方法（level>=2 默认开启）")
    p.add_argument("--no-attrs", dest="attrs", action="store_false", help="不重命名私有属性")
    p.add_argument("--shuffle", dest="shuffle", action="store_true", default=None, help="打乱顶层函数顺序（level 3 默认开启，仅限无定义期依赖的函数）")
    p.add_argument("--no-shuffle", dest="shuffle", action="store_false", help="不打乱顶层函数顺序")
    p.add_argument("--rename-args", action="store_true", help="实验性：重命名函数参数（仅改写同文件内直接调用的关键字参数，跨文件关键字调用可能失效）")
    p.add_argument("--junk", dest="junk", action="store_true", default=None, help="插入死代码（level 3 默认开启）")
    p.add_argument("--no-junk", dest="junk", action="store_false", help="不插入死代码")
    p.add_argument("--keep-docstrings", dest="strip_docstrings", action="store_false", default=True, help="保留 docstring（默认删除）")
    p.add_argument("--keep-name", action="append", default=[], metavar="NAME", help="永不重命名的标识符，可重复指定")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="排除的文件 glob，可重复指定，如 'test_*.py'")
    p.add_argument("--map", dest="map_path", default=None, help="把 原名->混淆名 映射写到这个 JSON 文件（调试用，发布时不要分发）")
    p.add_argument("--dry-run", action="store_true", help="只检查并统计，不写输出文件")
    p.add_argument("--force", action="store_true", help="输出目录已存在时直接覆盖（默认已存在且非空时拒绝）")
    p.add_argument("-q", "--quiet", action="store_true", help="只输出错误和一行汇总")
    p.add_argument("-v", "--verbose", action="store_true", help="打印每个文件的统计")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    inp = Path(args.input)
    if not inp.exists():
        print(f"错误：输入不存在：{inp}", file=sys.stderr)
        return 2

    if args.output:
        out = Path(args.output)
    else:
        if inp.is_file():
            out = inp.with_name(inp.stem + "_obf" + inp.suffix)
        else:
            out = inp.with_name(inp.name + "_obf")

    if not args.dry_run and not args.force and out.exists() and out.is_dir():
        existing = [p for p in out.rglob("*.py") if p.is_file()]
        if existing:
            print(f"错误：输出目录已存在且有 .py 文件：{out}（加 --force 覆盖，或换个 -o）", file=sys.stderr)
            return 2

    seed = args.seed if args.seed is not None else str(random.randint(0, 2**31 - 1))
    if args.seed is None and not args.quiet:
        print(f"seed 未指定，本次随机 seed={seed}（用 --seed {seed} 可复现）")

    try:
        result = obfuscate_project(
            input_path=inp,
            output_path=out,
            seed=seed,
            level=args.level,
            rename_top=args.rename_top,
            rename_args=args.rename_args,
            encrypt_strings=args.strings,
            strip_docstrings=args.strip_docstrings,
            add_junk=args.junk,
            keep_names=set(args.keep_name),
            exclude=list(args.exclude),
            dry_run=args.dry_run,
            obfuscate_ints=args.ints,
            rename_attrs=args.attrs,
            shuffle_top=args.shuffle,
        )
    except ObfuscateError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1

    if args.map_path:
        try:
            write_mapping(result, Path(args.map_path))
        except OSError as exc:
            print(f"错误：写映射文件失败：{exc}", file=sys.stderr)
            return 1

    renamed = sum(f.renamed_locals + f.renamed_top + f.attrs_renamed for f in result.files)
    strings_n = sum(f.strings_encrypted for f in result.files)
    ints_n = sum(f.ints_obfuscated for f in result.files)
    bytes_n = sum(f.bytes_encrypted for f in result.files)
    if args.verbose:
        for f in result.files:
            print(f"  {f.rel}: 改名 {f.renamed_locals + f.renamed_top + f.attrs_renamed}（属性 {f.attrs_renamed}），字符串 {f.strings_encrypted}，bytes {f.bytes_encrypted}，整数 {f.ints_obfuscated}，乱序 {f.shuffled_defs}，{f.bytes_in} -> {f.bytes_out} 字节")
    if not args.quiet:
        mode = "试运行（未写文件）" if args.dry_run else f"已写到 {out}"
        print(f"完成：{len(result.files)} 个文件，改名 {renamed} 处，加密字符串 {strings_n} 个，bytes {bytes_n} 个，混淆整数 {ints_n} 个，{result.total_in} -> {result.total_out} 字节。{mode}")
        print(f"seed={seed} level={args.level}。注意：混淆不是加密，懂行的人仍可还原；映射文件不要随产物分发。")
    else:
        print(f"完成：{len(result.files)} 个文件 -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
