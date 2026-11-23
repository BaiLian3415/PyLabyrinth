"""AST transformer for pyobf v0.1alpha.2.

Safety-first rules (v0.1, kept in alpha.2):
- Never rename attributes (``obj.attr``), imports, builtins, dunders,
  decorators, or keyword-argument names of unknown callees.
- Local variables / loop / with / except / comprehension variables are
  renamed per-function-scope, so shadowing and closures stay correct.
- Function parameters are NOT renamed by default (keyword calls would
  break). ``--rename-args`` enables a signature-aware rewrite that only
  rewrites keyword args of direct calls to a known local function.
- Top-level (module) ``def``/``class`` names are only renamed at
  level >= 2, only if they start with ``_``, and only with a project-wide
  map built in a first pass, so cross-file ``from x import _helper`` and
  ``mod._helper`` are rewritten consistently.
- String encryption only applies to plain ``str`` constants >= 4 chars,
  never inside f-string literal parts, annotations, or docstrings.
  The decoded value is identical at runtime, so semantics are preserved
  (except pathological ``is`` checks on string literals).
"""
from __future__ import annotations

import ast
import hashlib
import keyword

from .naming import NameGenerator
from .strings import HELPER_NAME, encrypt_str_indexed

_DUNDER_OK = ("self", "cls")


class _Scope:
    __slots__ = ("kind", "bindings", "protected", "global_names", "nonlocal_names")

    def __init__(self, kind: str):
        self.kind = kind  # module | function | class | comp | lambda
        self.bindings: dict[str, str] = {}
        self.protected: set[str] = set()
        self.global_names: set[str] = set()
        self.nonlocal_names: set[str] = set()


class Renamer(ast.NodeTransformer):
    def __init__(
        self,
        *,
        seed: str,
        name_gen: NameGenerator,
        module_name: str,
        top_map: dict[str, str],
        global_top_maps: dict[str, dict[str, str]],
        rename_top: bool,
        rename_args: bool,
        encrypt_strings: bool,
        strip_docstrings: bool,
        keep_names: set[str],
        key: bytes | None = None,
        helper_name: str = HELPER_NAME,
        obfuscate_ints: bool = False,
        master: bytes | None = None,
    ):
        super().__init__()
        self.seed = seed
        self.name_gen = name_gen
        self.module_name = module_name
        self.top_map = top_map
        self.global_top_maps = global_top_maps
        self.rename_top = rename_top
        self.rename_args = rename_args
        self.encrypt_strings = encrypt_strings
        self.strip_docstrings = strip_docstrings
        self.keep_names = set(keep_names)
        # alpha.2: `master` is the per-string-salt master; `key` is kept
        # as an alias for callers still passing the old name.
        self.master = master if master is not None else key
        self.key = self.master
        self.helper_name = helper_name
        self.obfuscate_ints = obfuscate_ints

        self.scopes: list[_Scope] = []
        self._path: list[str] = []  # qualified function/class names
        self._in_annotation = 0
        self._in_match = 0
        self._in_all = False
        self._str_index = 0
        self._int_index = 0
        self.imported_modules: dict[str, str] = {}  # alias -> module name

        self.stats = {"renamed_locals": 0, "renamed_top": 0, "strings_encrypted": 0, "ints_obfuscated": 0}
        # original -> obfuscated, scope-qualified keys for the map file
        self.mapping: dict[str, str] = {}
        # simple function name -> {param original: param obfuscated}
        self.sig_maps: dict[str, dict[str, str]] = {}

    # ------------------------------------------------------------------
    # scope helpers
    # ------------------------------------------------------------------
    def _scope_key(self) -> str:
        return f"{self.module_name}:{'.'.join(self._path) if self._path else '<module>'}"

    def _current(self) -> _Scope:
        return self.scopes[-1]

    def _lookup(self, name: str) -> str | None:
        # Walk outwards; global/nonlocal declarations redirect the search.
        for i in range(len(self.scopes) - 1, -1, -1):
            scope = self.scopes[i]
            if name in scope.global_names:
                # only the module scope can answer
                continue
            if name in scope.nonlocal_names and scope.kind == "function":
                continue
            if name in scope.bindings:
                return scope.bindings[name]
            if name in scope.protected:
                return None
            if scope.kind == "function" and name in scope.global_names:
                continue
        return None

    def _define(self, name: str) -> str:
        if not name or name in self.keep_names:
            return name
        if name.startswith("__") and name.endswith("__"):
            return name
        if keyword.iskeyword(name):
            return name
        cur = self._current()
        if cur.kind == "class":
            return name  # class-body assignment = attribute, not a local
        if cur.kind == "module":
            if self.rename_top and name in self.top_map:
                return self.top_map[name]
            return name
        if name in cur.global_names:
            if name in self.top_map:
                return self.top_map[name]
            return name
        if name in cur.nonlocal_names:
            # defined in an outer function scope; find it there
            for scope in reversed(self.scopes[:-1]):
                if name in scope.bindings:
                    return scope.bindings[name]
            return name
        if name in cur.bindings:
            return cur.bindings[name]
        if name in cur.protected:
            return name
        obf = self.name_gen.generate(name, self._scope_key())
        cur.bindings[name] = obf
        qkey = f"{self._scope_key()}:{name}"
        if qkey not in self.mapping:
            self.mapping[qkey] = obf
            self.stats["renamed_locals"] += 1
        return obf

    # ------------------------------------------------------------------
    # module / function / class
    # ------------------------------------------------------------------
    def transform(self, tree: ast.Module) -> ast.Module:
        if self.rename_args:
            self._prescan_signatures(tree)
        result = self.visit(tree)
        ast.fix_missing_locations(result)
        return result

    def _all_args(self, args: ast.arguments) -> list[ast.arg]:
        out: list[ast.arg] = []
        out.extend(args.posonlyargs)
        out.extend(args.args)
        out.extend(args.kwonlyargs)
        if args.vararg:
            out.append(args.vararg)
        if args.kwarg:
            out.append(args.kwarg)
        return out

    def _prescan_signatures(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            pmap: dict[str, str] = {}
            for arg in self._all_args(node.args):
                if arg.arg in _DUNDER_OK:
                    pmap[arg.arg] = arg.arg
                else:
                    pmap[arg.arg] = self.name_gen.generate(
                        arg.arg, f"{self.module_name}:{node.name}:args"
                    )
            self.sig_maps[node.name] = pmap
            if node.name in self.top_map:
                self.sig_maps[self.top_map[node.name]] = pmap

    def _strip_docstring(self, body: list[ast.stmt]) -> list[ast.stmt]:
        if not self.strip_docstrings or not body:
            return body
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            return body[1:]
        return body

    def visit_Module(self, node: ast.Module) -> ast.Module:
        scope = _Scope("module")
        scope.bindings.update(self.top_map)
        self.scopes.append(scope)
        node.body = self._strip_docstring(node.body)
        node.body = [self.visit(stmt) for stmt in node.body]
        self.scopes.pop()
        return node

    def _handle_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> ast.FunctionDef | ast.AsyncFunctionDef:
        orig_name = node.name
        is_module_level = len(self.scopes) == 1 and self.scopes[0].kind == "module"
        is_class_level = self.scopes and self.scopes[-1].kind == "class"
        if is_module_level and self.rename_top and orig_name in self.top_map:
            node.name = self.top_map[orig_name]
            self.stats["renamed_top"] += 1
            self.mapping[f"{self.module_name}:{orig_name}"] = node.name
        elif is_class_level:
            pass  # method name is an attribute; keep it
        elif not is_module_level:
            node.name = self._define(orig_name)

        # decorators / defaults / return annotation: outer scope
        node.decorator_list = [self.visit(d) for d in node.decorator_list]
        if node.args.defaults:
            node.args.defaults = [self.visit(d) for d in node.args.defaults]
        if node.args.kw_defaults:
            node.args.kw_defaults = [self.visit(d) if d is not None else None for d in node.args.kw_defaults]
        if node.returns is not None:
            self._in_annotation += 1
            node.returns = self.visit(node.returns)
            self._in_annotation -= 1

        # new function scope
        self.scopes.append(_Scope("function"))
        self._path.append(orig_name)
        # global / nonlocal pre-scan (direct statements only)
        for stmt in node.body:
            if isinstance(stmt, ast.Global):
                self.scopes[-1].global_names.update(stmt.names)
            elif isinstance(stmt, ast.Nonlocal):
                self.scopes[-1].nonlocal_names.update(stmt.names)

        pmap = self.sig_maps.get(orig_name) or self.sig_maps.get(node.name)
        for arg in self._all_args(node.args):
            if arg.annotation is not None:
                self._in_annotation += 1
                arg.annotation = self.visit(arg.annotation)
                self._in_annotation -= 1
            if arg.arg in _DUNDER_OK:
                self.scopes[-1].bindings[arg.arg] = arg.arg
                continue
            if self.rename_args and pmap and arg.arg in pmap:
                obf = pmap[arg.arg]
                self.scopes[-1].bindings[arg.arg] = obf
                arg.arg = obf
            else:
                # identity binding: lookups inside must find the arg itself
                self.scopes[-1].bindings[arg.arg] = arg.arg

        node.body = self._strip_docstring(node.body)
        node.body = [self.visit(stmt) for stmt in node.body]
        self._path.pop()
        self.scopes.pop()
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        return self._handle_function(node)  # type: ignore[return-value]

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        return self._handle_function(node)  # type: ignore[return-value]

    def visit_Lambda(self, node: ast.Lambda) -> ast.Lambda:
        # defaults in outer scope, body in lambda scope
        node.args.defaults = [self.visit(d) for d in node.args.defaults]
        node.args.kw_defaults = [self.visit(d) if d is not None else None for d in node.args.kw_defaults]
        self.scopes.append(_Scope("lambda"))
        self._path.append("<lambda>")
        for arg in self._all_args(node.args):
            if arg.annotation is not None:
                self._in_annotation += 1
                arg.annotation = self.visit(arg.annotation)
                self._in_annotation -= 1
            if self.rename_args:
                obf = self.name_gen.generate(arg.arg, f"{self.module_name}:<lambda>:args")
                self.scopes[-1].bindings[arg.arg] = obf
                arg.arg = obf
            else:
                self.scopes[-1].bindings[arg.arg] = arg.arg
        node.body = self.visit(node.body)
        self._path.pop()
        self.scopes.pop()
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        orig_name = node.name
        is_module_level = len(self.scopes) == 1 and self.scopes[0].kind == "module"
        is_class_level = self.scopes and self.scopes[-1].kind == "class"
        if is_module_level and self.rename_top and orig_name in self.top_map:
            node.name = self.top_map[orig_name]
            self.stats["renamed_top"] += 1
            self.mapping[f"{self.module_name}:{orig_name}"] = node.name
        elif is_class_level:
            pass
        elif not is_module_level:
            node.name = self._define(orig_name)

        node.decorator_list = [self.visit(d) for d in node.decorator_list]
        node.bases = [self.visit(b) for b in node.bases]
        node.keywords = [self.visit(k) for k in node.keywords]

        self.scopes.append(_Scope("class"))
        self._path.append(orig_name)
        node.body = self._strip_docstring(node.body)
        node.body = [self.visit(stmt) for stmt in node.body]
        self._path.pop()
        self.scopes.pop()
        return node

    # ------------------------------------------------------------------
    # names / targets
    # ------------------------------------------------------------------
    def visit_Name(self, node: ast.Name) -> ast.Name:
        if isinstance(node.ctx, ast.Store):
            node.id = self._define(node.id)
        else:  # Load / Del
            obf = self._lookup(node.id)
            if obf is not None:
                node.id = obf
        return node

    def _define_target(self, node: ast.AST) -> ast.AST:
        if isinstance(node, ast.Name):
            node.id = self._define(node.id)
            return node
        if isinstance(node, (ast.Tuple, ast.List)):
            node.elts = [self._define_target(e) for e in node.elts]  # type: ignore[assignment]
            return node
        if isinstance(node, ast.Starred):
            node.value = self._define_target(node.value)  # type: ignore[assignment]
            return node
        # Attribute / Subscript: only their inner value is a name
        return self.visit(node)

    def visit_Assign(self, node: ast.Assign) -> ast.Assign:
        is_all = (
            len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "__all__"
        )
        # value first: `x = x + 1` must read the old binding
        if is_all:
            self._in_all = True
            node.value = self.visit(node.value)
            self._in_all = False
        else:
            node.value = self.visit(node.value)
        node.targets = [self._define_target(t) for t in node.targets]  # type: ignore[assignment]
        return node

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.AnnAssign:
        self._in_annotation += 1
        node.annotation = self.visit(node.annotation)
        self._in_annotation -= 1
        if node.value is not None:
            node.value = self.visit(node.value)
        if node.target is not None:
            node.target = self._define_target(node.target)  # type: ignore[assignment]
        return node

    def visit_AugAssign(self, node: ast.AugAssign) -> ast.AugAssign:
        node.value = self.visit(node.value)
        node.target = self._define_target(node.target)  # type: ignore[assignment]
        return node

    def visit_NamedExpr(self, node: ast.NamedExpr) -> ast.NamedExpr:
        node.value = self.visit(node.value)
        node.target = self._define_target(node.target)  # type: ignore[assignment]
        return node

    def visit_For(self, node: ast.For) -> ast.For:
        node.iter = self.visit(node.iter)
        node.target = self._define_target(node.target)  # type: ignore[assignment]
        node.body = [self.visit(s) for s in node.body]
        node.orelse = [self.visit(s) for s in node.orelse]
        return node

    def visit_AsyncFor(self, node: ast.AsyncFor) -> ast.AsyncFor:
        node.iter = self.visit(node.iter)
        node.target = self._define_target(node.target)  # type: ignore[assignment]
        node.body = [self.visit(s) for s in node.body]
        node.orelse = [self.visit(s) for s in node.orelse]
        return node

    def visit_With(self, node: ast.With) -> ast.With:
        for item in node.items:
            item.context_expr = self.visit(item.context_expr)
            if item.optional_vars is not None:
                item.optional_vars = self._define_target(item.optional_vars)  # type: ignore[assignment]
        node.body = [self.visit(s) for s in node.body]
        return node

    def visit_AsyncWith(self, node: ast.AsyncWith) -> ast.AsyncWith:
        for item in node.items:
            item.context_expr = self.visit(item.context_expr)
            if item.optional_vars is not None:
                item.optional_vars = self._define_target(item.optional_vars)  # type: ignore[assignment]
        node.body = [self.visit(s) for s in node.body]
        return node

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> ast.ExceptHandler:
        if node.type is not None:
            node.type = self.visit(node.type)
        if node.name:
            node.name = self._define(node.name)
        node.body = [self.visit(s) for s in node.body]
        return node

    def visit_Global(self, node: ast.Global) -> ast.Global:
        if self.scopes:
            self.scopes[-1].global_names.update(node.names)
        return node

    def visit_Nonlocal(self, node: ast.Nonlocal) -> ast.Nonlocal:
        if self.scopes:
            self.scopes[-1].nonlocal_names.update(node.names)
        return node

    # ------------------------------------------------------------------
    # comprehensions: first iter is evaluated in the enclosing scope
    # ------------------------------------------------------------------
    def _visit_comprehension(self, node: ast.comprehension, is_first: bool) -> ast.comprehension:
        if is_first:
            node.iter = self.visit(node.iter)
            node.target = self._define_target(node.target)  # type: ignore[assignment]
        else:
            node.target = self._define_target(node.target)  # type: ignore[assignment]
            node.iter = self.visit(node.iter)
        node.ifs = [self.visit(c) for c in node.ifs]
        return node

    def _visit_comp(
        self, node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp
    ):
        self.scopes.append(_Scope("comp"))
        self._path.append("<comp>")
        for i, gen in enumerate(node.generators):
            node.generators[i] = self._visit_comprehension(gen, is_first=(i == 0))
        if isinstance(node, ast.DictComp):
            node.key = self.visit(node.key)
            node.value = self.visit(node.value)
        else:
            node.elt = self.visit(node.elt)
        self._path.pop()
        self.scopes.pop()
        return node

    def visit_ListComp(self, node: ast.ListComp) -> ast.ListComp:
        return self._visit_comp(node)

    def visit_SetComp(self, node: ast.SetComp) -> ast.SetComp:
        return self._visit_comp(node)

    def visit_DictComp(self, node: ast.DictComp) -> ast.DictComp:
        return self._visit_comp(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> ast.GeneratorExp:
        return self._visit_comp(node)

    # ------------------------------------------------------------------
    # imports / attributes / calls
    # ------------------------------------------------------------------
    def _resolve_module(self, level: int, module: str | None) -> str:
        if level == 0:
            return module or ""
        package = self.module_name.rpartition(".")[0] if "." in self.module_name else ""
        parts = package.split(".") if package else []
        if level > 1:
            cut = level - 1
            parts = parts[:-cut] if len(parts) >= cut else []
        base = ".".join(parts)
        if module:
            return f"{base}.{module}" if base else module
        return base

    def visit_Import(self, node: ast.Import) -> ast.Import:
        for alias in node.names:
            bound = alias.asname or alias.name.split(".")[0]
            self._current().protected.add(bound)
            if alias.asname:
                self.imported_modules[alias.asname] = alias.name
            else:
                self.imported_modules[alias.name.split(".")[0]] = alias.name.split(".")[0]
        return node

    def visit_ImportFrom(self, node: ast.ImportFrom) -> ast.ImportFrom:
        src_module = self._resolve_module(node.level, node.module)
        src_top = self.global_top_maps.get(src_module, {})
        for alias in node.names:
            if alias.name == "*":
                continue
            if alias.name in src_top:
                obf = src_top[alias.name]
                # binding in this file becomes the obfuscated name
                self._current().bindings[alias.name] = obf
                alias.name = obf
                if alias.asname:
                    self._current().protected.add(alias.asname)
            else:
                bound = alias.asname or alias.name
                self._current().protected.add(bound)
        return node

    def visit_Attribute(self, node: ast.Attribute) -> ast.Attribute:
        node.value = self.visit(node.value)
        if isinstance(node.value, ast.Name) and node.value.id in self.imported_modules:
            mod = self.imported_modules[node.value.id]
            top = self.global_top_maps.get(mod, {})
            if node.attr in top:
                node.attr = top[node.attr]
        # never rename the attribute itself otherwise
        return node

    def visit_Call(self, node: ast.Call) -> ast.Call:
        orig_callee = node.func.id if isinstance(node.func, ast.Name) else None
        node.func = self.visit(node.func)
        node.args = [self.visit(a) for a in node.args]
        for kw in node.keywords:
            if kw.value is not None:
                kw.value = self.visit(kw.value)
            if (
                self.rename_args
                and kw.arg
                and orig_callee
                and orig_callee in self.sig_maps
                and kw.arg in self.sig_maps[orig_callee]
            ):
                kw.arg = self.sig_maps[orig_callee][kw.arg]
        return node

    # ------------------------------------------------------------------
    # strings
    # ------------------------------------------------------------------
    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.JoinedStr:
        # Literal parts stay literal; formatted values are normal exprs.
        new_values: list[ast.AST] = []
        for v in node.values:
            if isinstance(v, ast.FormattedValue):
                new_values.append(self.visit(v))
            else:
                new_values.append(v)  # Constant literal part: do not encrypt
        node.values = new_values  # type: ignore[assignment]
        return node

    def visit_Match(self, node: ast.Match) -> ast.Match:
        # Patterns must stay literal: `case 5:` / `case "x":` cannot be
        # replaced by a call or an arithmetic expression.
        node.subject = self.visit(node.subject)
        for case in node.cases:
            self._in_match += 1
            case.pattern = self.visit(case.pattern)
            self._in_match -= 1
            if case.guard is not None:
                case.guard = self.visit(case.guard)
            case.body = [self.visit(s) for s in case.body]
        return node

    def _obfuscate_int(self, node: ast.Constant) -> ast.AST:
        n = node.value
        assert type(n) is int
        digest = hashlib.sha256(
            f"{self.seed}\x00{self.module_name}\x00int\x00{n}\x00{self._int_index}".encode("utf-8")
        ).hexdigest()
        self._int_index += 1
        # deterministic split n = a + b, a in [-5000, 5000]
        a = int(digest[:4], 16) % 10001 - 5000
        b = n - a
        self.stats["ints_obfuscated"] += 1
        expr = ast.BinOp(
            left=ast.Constant(value=a),
            op=ast.Add(),
            right=ast.Constant(value=b),
        )
        return ast.copy_location(expr, node)

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        # ints first (bool is a subclass of int: check exact type)
        if type(node.value) is int:
            if not self.obfuscate_ints:
                return node
            if self._in_annotation > 0 or self._in_match > 0:
                return node
            if abs(node.value) < 10:
                return node  # 0/1/2/-1 and small indices stay readable
            return self._obfuscate_int(node)
        if not isinstance(node.value, str):
            return node
        if self._in_annotation > 0 or self._in_match > 0:
            return node
        if not self.encrypt_strings:
            return node
        text = node.value
        if self._in_all and text in self.top_map:
            text = self.top_map[text]
        if len(text) < 4:
            # short strings: keep them, encryption is pure overhead
            if text != node.value:
                return ast.Constant(value=text)
            return node
        assert self.master is not None
        encoded = encrypt_str_indexed(text, self.master, self.seed, self.module_name, self._str_index)
        self._str_index += 1
        self.stats["strings_encrypted"] += 1
        call = ast.Call(
            func=ast.Name(id=self.helper_name, ctx=ast.Load()),
            args=[ast.Constant(value=encoded)],
            keywords=[],
        )
        return ast.copy_location(call, node)
