"""VMP for pyobf v0.1alpha.6: compile a simple function to custom bytecode.

Alpha.6 hardens the VM itself:
- opcode numbers are permuted per file (seed + module), so the same
  logical op has a different numeric value in every file;
- the whole payload is XORed with an LCG key stream (key derived
  from seed + module) and carries a SHA256 checksum, so the payload
  bytes reveal neither opcodes nor constants, and tampering is
  detected before execution;
- junk NOP instructions are inserted into the bytecode (jump targets
  adjusted), so the instruction stream is longer than the logic.

A function that fits the supported subset is replaced by a stub that
calls the embedded stack-VM interpreter with a base64 payload. The
original logic (arithmetic, branches, loops, calls) is no longer
visible as Python source at all -- only the interpreter and the
opaque payload remain.

Supported subset (anything else -> the function is left alone):
- top-level ``def`` only, no async, no ``*args``/``**kwargs``
- statements: Assign, AugAssign, Expr, Return, If, While, For,
  Break, Continue, Pass (no try/with/match/comprehension/lambda/
  nested def, yield, global/nonlocal, raise, assert, import, del)
- expressions: constants (int/float/str/bool/None/bytes),
  Name, BinOp, UnaryOp, BoolOp (and/or, short-circuit),
  single Compare, IfExp, Call (positional args only),
  Subscript (index or slice), List/Tuple literals, Attribute
  load/store. No dict/set literals, no f-strings, no walrus.

Safety: the compiler is conservative -- anything it does not
recognise makes the function ineligible, so an unsupported
function is never half-compiled. Globals are translated through
``global_map`` (original name -> runtime name) so cross-file
private names renamed by the top map still resolve.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import random
import struct

# opcodes
OP_LOAD_CONST = 0
OP_LOAD_LOCAL = 1
OP_STORE_LOCAL = 2
OP_LOAD_GLOBAL = 3
OP_LOAD_ATTR = 4
OP_STORE_ATTR = 5
OP_BINARY = 6
OP_UNARY = 7
OP_COMPARE = 8
OP_POP_JUMP_IF_FALSE = 9
OP_JUMP = 10
OP_POP_TOP = 11
OP_RETURN = 12
OP_CALL = 13
OP_BUILD_LIST = 14
OP_BUILD_TUPLE = 15
OP_SUBSCR = 16
OP_GET_ITER = 17
OP_FOR_ITER = 18
OP_POP_JUMP_IF_TRUE = 19
OP_DUP_TOP = 20
OP_STORE_SUBSCR = 21
OP_DUP_TOP_TWO = 22
OP_UNPACK_SEQ = 23
OP_BUILD_SLICE = 24
OP_NOP = 25

N_OPS = 26
_JUMP_OPS = frozenset({OP_POP_JUMP_IF_FALSE, OP_JUMP, OP_POP_JUMP_IF_TRUE, OP_FOR_ITER})


def perm_for(seed: str, module: str) -> list[int]:
    """Per-file opcode permutation: perm[logical op] = numeric op."""
    rng = random.Random(int(hashlib.sha256(f"{seed}\x00{module}\x00vm-perm".encode()).hexdigest()[:8], 16))
    perm = list(range(N_OPS))
    rng.shuffle(perm)
    return perm


def key_for(seed: str, module: str) -> int:
    """Per-file payload key (non-zero, 31-bit for the LCG stream)."""
    key = int(hashlib.sha256(f"{seed}\x00{module}\x00vm-key".encode()).hexdigest()[:8], 16) & 0x7FFFFFFF
    return key or 0x5EED123


def _xor_stream(data: bytes, key_int: int) -> bytes:
    """LCG key stream (its own inverse). Must match the interpreter."""
    out = bytearray(data)
    state = key_int & 0x7FFFFFFF
    for i in range(len(out)):
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        out[i] ^= (state >> 16) & 0xFF
    return bytes(out)

_BINOPS = {
    ast.Add: 0, ast.Sub: 1, ast.Mult: 2, ast.FloorDiv: 3, ast.Div: 4,
    ast.Mod: 5, ast.Pow: 6, ast.LShift: 7, ast.RShift: 8, ast.BitOr: 9,
    ast.BitXor: 10, ast.BitAnd: 11, ast.MatMult: 12,
}
_UNOPS = {ast.Invert: 0, ast.Not: 1, ast.USub: 2, ast.UAdd: 3}
_CMPOPS = {
    ast.Eq: 0, ast.NotEq: 1, ast.Lt: 2, ast.LtE: 3, ast.Gt: 4, ast.GtE: 5,
    ast.In: 6, ast.NotIn: 7, ast.Is: 8, ast.IsNot: 9,
}

# nodes that make a function ineligible, anywhere inside it
_FORBIDDEN = (
    ast.Try, ast.TryStar, ast.With, ast.AsyncWith, ast.AsyncFor,
    ast.AsyncFunctionDef, ast.Match, ast.Lambda, ast.FunctionDef,
    ast.ClassDef, ast.Yield, ast.YieldFrom, ast.Await, ast.Global,
    ast.Nonlocal, ast.Delete, ast.Assert, ast.Raise, ast.Import,
    ast.ImportFrom, ast.NamedExpr, ast.JoinedStr, ast.FormattedValue,
    ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp,
    ast.Dict, ast.Set, ast.Starred, ast.AnnAssign,
)


class NotVMable(Exception):
    pass


def _const_key(value) -> tuple:
    if value is None:
        return ("none",)
    if value is True:
        return ("true",)
    if value is False:
        return ("false",)
    if type(value) is int:
        return ("int", value)
    if type(value) is float:
        return ("float", value)
    if type(value) is str:
        return ("str", value)
    if type(value) is bytes:
        return ("bytes", value)
    raise NotVMable(f"unsupported constant {value!r}")


class _Compiler:
    def __init__(self, func: ast.FunctionDef, global_map: dict[str, str],
                 attr_map: dict[tuple[str, str], str], imported_aliases: set[str],
                 perm: list[int] | None = None, key_int: int = 0,
                 seed: str = "", module: str = ""):
        self.func = func
        self.global_map = global_map
        self.attr_map = attr_map
        self.imported_aliases = imported_aliases
        self.perm = perm if perm is not None else list(range(N_OPS))
        self.key_int = key_int
        self.seed = seed
        self.module = module
        self.locals: list[str] = []
        self._local_idx: dict[str, int] = {}
        self.consts: list = []
        self._const_idx: dict[tuple, int] = {}
        self.code: list[list[int]] = []  # [op, arg], mutable for patching
        self._loops: list[dict[str, list[int]]] = []  # {"break": [...], "continue": target}

        for arg in func.args.posonlyargs + func.args.args + func.args.kwonlyargs:
            self._add_local(arg.arg)
        for node in ast.walk(func):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                self._add_local(node.id)

    def _add_local(self, name: str) -> int:
        if name not in self._local_idx:
            self._local_idx[name] = len(self.locals)
            self.locals.append(name)
        return self._local_idx[name]

    def _const(self, value) -> int:
        key = _const_key(value)
        if key not in self._const_idx:
            self._const_idx[key] = len(self.consts)
            self.consts.append(value)
        return self._const_idx[key]

    def _emit(self, op: int, arg: int = 0) -> int:
        self.code.append([op, arg])
        return len(self.code) - 1

    def _patch(self, idx: int) -> None:
        self.code[idx][1] = len(self.code)

    def compile(self) -> bytes:
        for stmt in self.func.body:
            self._stmt(stmt)
        self._emit(OP_LOAD_CONST, self._const(None))
        self._emit(OP_RETURN)
        self._insert_nops()
        plain = _encode(self.code, self.consts, len(self.locals), self.perm)
        if not self.key_int:
            return plain
        sealed = hashlib.sha256(plain).digest()[:4] + plain
        return _xor_stream(sealed, self.key_int)

    def _insert_nops(self) -> None:
        """Insert junk NOPs into the bytecode (alpha.6).

        A NOP falls through to the next instruction, so inserting one
        is always safe as long as jump targets past the insertion
        point are shifted by one; a jump landing exactly on the NOP
        just falls through to the original target.
        """
        if not self.seed:
            return
        rng = random.Random(int(hashlib.sha256(
            f"{self.seed}\x00{self.module}\x00{self.func.name}\x00vm-nop".encode()
        ).hexdigest()[:8], 16))
        n = min(5, max(2, len(self.code) // 10))
        for _ in range(n):
            pos = rng.randint(0, len(self.code))
            self.code.insert(pos, [OP_NOP, 0])
            for instr in self.code:
                if instr[0] in _JUMP_OPS and instr[1] > pos:
                    instr[1] += 1

    # ------------------------------------------------------------- stmts
    def _stmt(self, node: ast.AST) -> None:
        if isinstance(node, ast.Expr):
            self._expr(node.value)
            self._emit(OP_POP_TOP)
        elif isinstance(node, ast.Assign):
            if len(node.targets) != 1:
                raise NotVMable("multi-target assign")
            target = node.targets[0]
            if isinstance(target, ast.Attribute):
                # object first, then value: [obj, value] -> STORE_ATTR
                self._expr(target.value)
                self._expr(node.value)
                self._emit(OP_STORE_ATTR, self._attr_const(target))
            elif isinstance(target, ast.Subscript):
                if isinstance(target.slice, ast.Slice):
                    raise NotVMable("slice assign")
                self._expr(target.value)
                self._expr(target.slice)
                self._expr(node.value)
                self._emit(OP_STORE_SUBSCR)
            else:
                self._expr(node.value)
                self._store_target(target)
        elif isinstance(node, ast.AugAssign):
            self._augassign(node)
        elif isinstance(node, ast.Return):
            if node.value is not None:
                self._expr(node.value)
            else:
                self._emit(OP_LOAD_CONST, self._const(None))
            self._emit(OP_RETURN)
        elif isinstance(node, ast.If):
            self._stmt_if(node)
        elif isinstance(node, ast.While):
            self._stmt_while(node)
        elif isinstance(node, ast.For):
            self._stmt_for(node)
        elif isinstance(node, ast.Break):
            if not self._loops:
                raise NotVMable("break outside loop")
            self._loops[-1]["break"].append(self._emit(OP_JUMP, 0))
        elif isinstance(node, ast.Continue):
            if not self._loops:
                raise NotVMable("continue outside loop")
            self._emit(OP_JUMP, self._loops[-1]["continue"])
        elif isinstance(node, ast.Pass):
            pass
        else:
            raise NotVMable(f"unsupported statement {type(node).__name__}")

    def _stmt_list(self, stmts: list[ast.stmt]) -> None:
        for s in stmts:
            self._stmt(s)

    def _stmt_if(self, node: ast.If) -> None:
        self._expr(node.test)
        jf = self._emit(OP_POP_JUMP_IF_FALSE, 0)
        self._stmt_list(node.body)
        if node.orelse:
            j = self._emit(OP_JUMP, 0)
            self._patch(jf)
            self._stmt_list(node.orelse)
            self._patch(j)
        else:
            self._patch(jf)

    def _stmt_while(self, node: ast.While) -> None:
        if node.orelse:
            raise NotVMable("while/else")
        start = len(self.code)
        self._expr(node.test)
        jf = self._emit(OP_POP_JUMP_IF_FALSE, 0)
        frame = {"break": [], "continue": start}
        self._loops.append(frame)
        self._stmt_list(node.body)
        self._loops.pop()
        self._emit(OP_JUMP, start)
        self._patch(jf)
        for b in frame["break"]:
            self.code[b][1] = len(self.code)

    def _stmt_for(self, node: ast.For) -> None:
        if node.orelse:
            raise NotVMable("for/else")
        self._expr(node.iter)
        self._emit(OP_GET_ITER)
        start = len(self.code)
        fi = self._emit(OP_FOR_ITER, 0)
        self._store_target(node.target)
        frame = {"break": [], "continue": start}
        self._loops.append(frame)
        self._stmt_list(node.body)
        self._loops.pop()
        self._emit(OP_JUMP, start)
        end = len(self.code)
        self.code[fi][1] = end
        for b in frame["break"]:
            self.code[b][1] = end

    # ------------------------------------------------------------- targets
    def _store_target(self, target: ast.AST) -> None:
        # Value is already on the stack. Only Name / Tuple / List
        # targets reach here; Attribute / Subscript are handled in
        # _stmt (object/container must be emitted before the value).
        if isinstance(target, ast.Name):
            self._emit(OP_STORE_LOCAL, self._add_local(target.id))
        elif isinstance(target, (ast.Tuple, ast.List)):
            n = len(target.elts)
            self._emit(OP_UNPACK_SEQ, n)
            for elt in reversed(target.elts):
                self._store_target(elt)
        else:
            raise NotVMable(f"unsupported assign target {type(target).__name__}")

    def _augassign(self, node: ast.AugAssign) -> None:
        op = _BINOPS.get(type(node.op))
        if op is None:
            raise NotVMable(f"unsupported aug op {type(node.op).__name__}")
        target = node.target
        if isinstance(target, ast.Name):
            self._emit(OP_LOAD_LOCAL, self._add_local(target.id))
            self._expr(node.value)
            self._emit(OP_BINARY, op)
            self._emit(OP_STORE_LOCAL, self._add_local(target.id))
        elif isinstance(target, ast.Attribute):
            self._expr(target.value)
            self._emit(OP_DUP_TOP)
            self._emit(OP_LOAD_ATTR, self._attr_const(target))
            self._expr(node.value)
            self._emit(OP_BINARY, op)
            self._emit(OP_STORE_ATTR, self._attr_const(target))
        elif isinstance(target, ast.Subscript):
            self._expr(target.value)
            self._expr(target.slice)
            self._emit(OP_DUP_TOP_TWO)
            self._emit(OP_SUBSCR)
            self._expr(node.value)
            self._emit(OP_BINARY, op)
            self._emit(OP_STORE_SUBSCR)
        else:
            raise NotVMable("unsupported aug target")

    # ------------------------------------------------------------- exprs
    def _attr_const(self, node: ast.Attribute) -> int:
        if isinstance(node.value, ast.Name) and node.value.id in self.imported_aliases:
            key = (node.value.id, node.attr)
            if key in self.attr_map:
                return self._const(self.attr_map[key])
            if node.attr.startswith("_"):
                raise NotVMable("private attr on imported module")
        return self._const(node.attr)

    def _expr(self, node: ast.AST) -> None:
        if isinstance(node, ast.Constant):
            self._emit(OP_LOAD_CONST, self._const(node.value))
        elif isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Load):
                if node.id in self._local_idx:
                    self._emit(OP_LOAD_LOCAL, self._local_idx[node.id])
                else:
                    self._emit(OP_LOAD_GLOBAL, self._const(self.global_map.get(node.id, node.id)))
            else:
                raise NotVMable("Name store in expression position")
        elif isinstance(node, ast.BinOp):
            op = _BINOPS.get(type(node.op))
            if op is None:
                raise NotVMable(f"unsupported binop {type(node.op).__name__}")
            self._expr(node.left)
            self._expr(node.right)
            self._emit(OP_BINARY, op)
        elif isinstance(node, ast.UnaryOp):
            op = _UNOPS.get(type(node.op))
            if op is None:
                raise NotVMable(f"unsupported unary {type(node.op).__name__}")
            self._expr(node.operand)
            self._emit(OP_UNARY, op)
        elif isinstance(node, ast.BoolOp):
            self._boolop(node)
        elif isinstance(node, ast.Compare):
            if len(node.ops) != 1 or len(node.comparators) != 1:
                raise NotVMable("chained compare")
            op = _CMPOPS.get(type(node.ops[0]))
            if op is None:
                raise NotVMable(f"unsupported compare {type(node.ops[0]).__name__}")
            self._expr(node.left)
            self._expr(node.comparators[0])
            self._emit(OP_COMPARE, op)
        elif isinstance(node, ast.IfExp):
            self._expr(node.test)
            jf = self._emit(OP_POP_JUMP_IF_FALSE, 0)
            self._expr(node.body)
            j = self._emit(OP_JUMP, 0)
            self._patch(jf)
            self._expr(node.orelse)
            self._patch(j)
        elif isinstance(node, ast.Call):
            if node.keywords or node.args and any(isinstance(a, ast.Starred) for a in node.args):
                raise NotVMable("keyword/star args in call")
            self._expr(node.func)
            for a in node.args:
                self._expr(a)
            self._emit(OP_CALL, len(node.args))
        elif isinstance(node, ast.Attribute):
            self._expr(node.value)
            self._emit(OP_LOAD_ATTR, self._attr_const(node))
        elif isinstance(node, ast.Subscript):
            self._expr(node.value)
            sl = node.slice
            if isinstance(sl, ast.Slice):
                if sl.lower is not None:
                    self._expr(sl.lower)
                else:
                    self._emit(OP_LOAD_CONST, self._const(None))
                if sl.upper is not None:
                    self._expr(sl.upper)
                else:
                    self._emit(OP_LOAD_CONST, self._const(None))
                if sl.step is not None:
                    self._expr(sl.step)
                    self._emit(OP_BUILD_SLICE, 3)
                else:
                    self._emit(OP_BUILD_SLICE, 2)
            else:
                self._expr(sl)
            self._emit(OP_SUBSCR)
        elif isinstance(node, ast.List):
            for elt in node.elts:
                self._expr(elt)
            self._emit(OP_BUILD_LIST, len(node.elts))
        elif isinstance(node, ast.Tuple):
            for elt in node.elts:
                self._expr(elt)
            self._emit(OP_BUILD_TUPLE, len(node.elts))
        else:
            raise NotVMable(f"unsupported expression {type(node).__name__}")

    def _boolop(self, node: ast.BoolOp) -> None:
        is_and = isinstance(node.op, ast.And)
        values = node.values
        self._expr(values[0])
        ends: list[int] = []
        for v in values[1:]:
            self._emit(OP_DUP_TOP)
            jf = self._emit(
                OP_POP_JUMP_IF_FALSE if is_and else OP_POP_JUMP_IF_TRUE, 0
            )
            self._emit(OP_POP_TOP)
            self._expr(v)
            ends.append(jf)
        for jf in ends:
            self._patch(jf)


# ------------------------------------------------------------------
# payload encoding
# ------------------------------------------------------------------
def _encode(code: list[list[int]], consts: list, nlocals: int,
            perm: list[int] | None = None) -> bytes:
    if perm is None:
        perm = list(range(N_OPS))
    out = bytearray()
    out += struct.pack(">HHH", len(code), len(consts), nlocals)
    for op, arg in code:
        out += struct.pack(">I", (perm[op] << 24) | arg)
    for c in consts:
        if c is None:
            out.append(0)
        elif c is True:
            out.append(1)
        elif c is False:
            out.append(2)
        elif type(c) is int:
            b = str(c).encode("utf-8")
            out.append(3)
            out += struct.pack(">I", len(b))
            out += b
        elif type(c) is float:
            out.append(4)
            out += struct.pack(">d", c)
        elif type(c) is str:
            b = c.encode("utf-8")
            out.append(5)
            out += struct.pack(">I", len(b))
            out += b
        elif type(c) is bytes:
            out.append(6)
            out += struct.pack(">I", len(c))
            out += c
        else:  # pragma: no cover
            raise NotVMable(f"cannot encode constant {c!r}")
    return bytes(out)


def executor_name_for(seed: str, module: str) -> str:
    digest = hashlib.sha256(f"{seed}\x00{module}\x00vm-exec".encode("utf-8")).hexdigest()
    return "_" + digest[:10]


def executor_source(exec_name: str, perm: list[int] | None = None,
                    key_int: int = 0) -> str:
    """Source of the embedded stack-VM interpreter.

    ``perm`` is the per-file opcode permutation (perm[logical] =
    numeric); the interpreter embeds its inverse. ``key_int`` is the
    per-file payload key; 0 means the payload is stored plain (tests
    only -- real runs always seal it).
    """
    if perm is None:
        perm = list(range(N_OPS))
    inv = [0] * N_OPS
    for logical, numeric in enumerate(perm):
        inv[numeric] = logical
    return f'''def {exec_name}(_p, _a, _g):
    import base64 as _b64
    import hashlib as _hl
    import operator as _om
    import struct as _st
    _d = _b64.b64decode(_p.encode("ascii"))
    _kk = {key_int}
    if _kk:
        _stt = _kk & 2147483647
        _db = bytearray(_d)
        for _i in range(len(_db)):
            _stt = (_stt * 1103515245 + 12345) & 2147483647
            _db[_i] ^= (_stt >> 16) & 255
        _d = bytes(_db)
        if _hl.sha256(_d[4:]).digest()[:4] != _d[:4]:
            raise ValueError("bad vm payload")
        _d = _d[4:]
    _pm = {inv!r}
    _n, _c, _l = _st.unpack(">HHH", _d[:6])
    _o = 6
    _code = []
    for _i in range(_n):
        _v = _st.unpack(">I", _d[_o:_o + 4])[0]
        _o += 4
        _code.append((_v >> 24, _v & 16777215))
    _k = []
    for _i in range(_c):
        _t = _d[_o]
        _o += 1
        if _t == 0:
            _k.append(None)
        elif _t == 1:
            _k.append(True)
        elif _t == 2:
            _k.append(False)
        elif _t == 3:
            _ln = _st.unpack(">I", _d[_o:_o + 4])[0]
            _o += 4
            _k.append(int(_d[_o:_o + _ln].decode("utf-8")))
            _o += _ln
        elif _t == 4:
            _k.append(_st.unpack(">d", _d[_o:_o + 8])[0])
            _o += 8
        elif _t == 5:
            _ln = _st.unpack(">I", _d[_o:_o + 4])[0]
            _o += 4
            _k.append(_d[_o:_o + _ln].decode("utf-8"))
            _o += _ln
        elif _t == 6:
            _ln = _st.unpack(">I", _d[_o:_o + 4])[0]
            _o += 4
            _k.append(_d[_o:_o + _ln])
            _o += _ln
    _b = _g.get("__builtins__")
    if not isinstance(_b, dict):
        _b = vars(_b)
    _loc = list(_a) + [None] * max(0, _l - len(_a))
    _s = []
    _pc = 0
    _bin = [_om.add, _om.sub, _om.mul, _om.floordiv, _om.truediv, _om.mod, _om.pow, _om.lshift, _om.rshift, _om.or_, _om.xor, _om.and_, _om.matmul]
    _un = [_om.invert, _om.not_, _om.neg, _om.pos]
    _cmp = [_om.eq, _om.ne, _om.lt, _om.le, _om.gt, _om.ge, _om.contains, None, _om.is_, _om.is_not]
    while True:
        _op, _x = _code[_pc]
        _pc += 1
        _op = _pm[_op]
        if _op == 25:
            pass
        elif _op == 0:
            _s.append(_k[_x])
        elif _op == 1:
            _s.append(_loc[_x])
        elif _op == 2:
            _loc[_x] = _s.pop()
        elif _op == 3:
            _nm = _k[_x]
            if _nm in _g:
                _s.append(_g[_nm])
            elif _nm in _b:
                _s.append(_b[_nm])
            else:
                raise NameError(_nm)
        elif _op == 4:
            _s.append(getattr(_s.pop(), _k[_x]))
        elif _op == 5:
            _v = _s.pop()
            setattr(_s.pop(), _k[_x], _v)
        elif _op == 6:
            _r = _s.pop()
            _s.append(_bin[_x](_s.pop(), _r))
        elif _op == 7:
            _s.append(_un[_x](_s.pop()))
        elif _op == 8:
            _r = _s.pop()
            _l2 = _s.pop()
            if _x == 6:
                _s.append(_cmp[_x](_r, _l2))
            elif _x == 7:
                _s.append(not _cmp[6](_r, _l2))
            else:
                _s.append(_cmp[_x](_l2, _r))
        elif _op == 9:
            if not _s.pop():
                _pc = _x
        elif _op == 10:
            _pc = _x
        elif _op == 11:
            _s.pop()
        elif _op == 12:
            return _s.pop()
        elif _op == 13:
            _args = _s[-_x:] if _x else []
            _fn = _s[-_x - 1]
            del _s[-_x - 1:]
            _s.append(_fn(*_args))
        elif _op == 14:
            _it = list(_s[-_x:]) if _x else []
            if _x:
                del _s[-_x:]
            _s.append(_it)
        elif _op == 15:
            _t = tuple(_s[-_x:]) if _x else ()
            if _x:
                del _s[-_x:]
            _s.append(_t)
        elif _op == 16:
            _i = _s.pop()
            _s.append(_s.pop()[_i])
        elif _op == 17:
            _s.append(iter(_s.pop()))
        elif _op == 18:
            try:
                _s.append(next(_s[-1]))
            except StopIteration:
                _s.pop()
                _pc = _x
        elif _op == 19:
            if _s.pop():
                _pc = _x
        elif _op == 20:
            _s.append(_s[-1])
        elif _op == 21:
            _v = _s.pop()
            _i = _s.pop()
            _s.pop()[_i] = _v
        elif _op == 22:
            _t1 = _s[-2]
            _t2 = _s[-1]
            _s.append(_t1)
            _s.append(_t2)
        elif _op == 23:
            _v = _s.pop()
            if len(_v) != _x:
                raise ValueError("unpack")
            _s.extend(_v)
        elif _op == 24:
            if _x == 3:
                _st2 = _s.pop()
                _up = _s.pop()
                _lo = _s.pop()
                _s.append(slice(_lo, _up, _st2))
            else:
                _up = _s.pop()
                _lo = _s.pop()
                _s.append(slice(_lo, _up))
'''


def _can_vm(func: ast.FunctionDef) -> bool:
    if func.args.vararg or func.args.kwarg:
        return False
    for node in ast.walk(func):
        if node is func:
            continue  # the root itself is a FunctionDef, not a nested one
        if isinstance(node, _FORBIDDEN):
            return False
        if isinstance(node, ast.Call) and (node.keywords or any(isinstance(a, ast.Starred) for a in node.args)):
            return False
        if isinstance(node, ast.Compare) and len(node.ops) != 1:
            return False
    return True


def _docstring_stmt(func: ast.FunctionDef) -> ast.Expr | None:
    if (
        func.body
        and isinstance(func.body[0], ast.Expr)
        and isinstance(func.body[0].value, ast.Constant)
        and isinstance(func.body[0].value.value, str)
    ):
        return func.body[0]
    return None


def apply_vmp(tree: ast.Module, seed: str, module: str,
              global_map: dict[str, str], attr_map: dict[tuple[str, str], str],
              imported_aliases: set[str]) -> tuple[int, str | None, list[int], int]:
    """Replace eligible top-level functions with VM stubs.

    Returns (number of functions VM'd, executor name or None,
    opcode permutation, payload key). The obfuscator needs the
    permutation and key to build the matching interpreter.
    """
    exec_name = executor_name_for(seed, module)
    perm = perm_for(seed, module)
    key_int = key_for(seed, module)
    count = 0
    new_body: list[ast.stmt] = []
    for stmt in tree.body:
        if not isinstance(stmt, ast.FunctionDef) or not _can_vm(stmt):
            new_body.append(stmt)
            continue
        try:
            payload = _Compiler(stmt, global_map, attr_map, imported_aliases,
                                perm=perm, key_int=key_int,
                                seed=seed, module=module).compile()
        except NotVMable:
            new_body.append(stmt)
            continue
        except Exception:
            new_body.append(stmt)
            continue
        b64 = base64.b64encode(payload).decode("ascii")
        arg_names = [a.arg for a in stmt.args.posonlyargs + stmt.args.args + stmt.args.kwonlyargs]
        args_tuple = ast.Tuple(
            elts=[ast.Name(id=n, ctx=ast.Load()) for n in arg_names],
            ctx=ast.Load(),
        )
        call = ast.Call(
            func=ast.Name(id=exec_name, ctx=ast.Load()),
            args=[
                ast.Constant(value=b64),
                args_tuple,
                ast.Call(func=ast.Name(id="globals", ctx=ast.Load()), args=[], keywords=[]),
            ],
            keywords=[],
        )
        stub = ast.FunctionDef(
            name=stmt.name,
            args=stmt.args,
            body=[],
            decorator_list=stmt.decorator_list,
            returns=stmt.returns,
            type_comment=stmt.type_comment,
        )
        doc = _docstring_stmt(stmt)
        if doc is not None:
            stub.body.append(doc)
        stub.body.append(ast.Return(value=call))
        ast.copy_location(stub, stmt)
        ast.fix_missing_locations(stub)
        new_body.append(stub)
        count += 1
    tree.body = new_body
    return count, (exec_name if count else None), perm, key_int
