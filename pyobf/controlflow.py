"""Control-flow obfuscation for pyobf v0.1alpha.6.

Three transforms, all AST-level and all semantics-preserving, applied
at level 3 (``--cf`` / ``--no-cf``):

1. Branch inversion: ``if cond: A else: B`` becomes
   ``if not cond: B else: A`` (deterministically chosen per If).
   The test is negated properly (``==`` <-> ``!=``, ``<`` <-> ``>=``,
   De Morgan for ``and``/``or``, unwrapping an existing ``not``).

2. While rewriting: ``while cond: body`` (no ``else``) becomes
   ``while True: if not cond: break; body``. The loop condition no
   longer sits in the ``while`` header.

3. Control-flow flattening: a function's top-level statements are
   split into blocks, each given a state number, and the body is
   replaced by a dispatcher::

       _cf_state = 0
       while True:
           if _cf_state == 3:
               <block 3>
               _cf_state = 1
           elif _cf_state == 0:
               <block 0>
               _cf_state = 2
           ...
           else:
               break

   The ``elif`` branches are shuffled, so reading top to bottom no
   longer reveals the execution order. ``if`` statements are split:
   the condition becomes its own state that jumps to the then-state
   or the else-state. Loops, ``try``/``with``, nested functions and
   class definitions are treated as single blocks that run to
   completion, so their internal control flow is untouched.

Safety: flattening is skipped for functions with ``yield``,
``global``/``nonlocal`` (the state variable must not disturb scope
directives), single-statement bodies (e.g. VM stubs), and async
functions. Anything the flattener does not understand is left in
its block as-is -- it never drops a statement.
"""
from __future__ import annotations

import ast
import hashlib
import random

_STATE_VAR = "_cf_state"


def _negate_test(test: ast.AST) -> ast.AST:
    """Return an AST node equivalent to ``not test``."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return test.operand
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        inv = {
            ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
            ast.Lt: ast.GtE, ast.LtE: ast.Gt,
            ast.Gt: ast.LtE, ast.GtE: ast.Lt,
            ast.In: ast.NotIn, ast.NotIn: ast.In,
            ast.Is: ast.IsNot, ast.IsNot: ast.Is,
        }
        op_type = type(test.ops[0])
        if op_type in inv:
            return ast.Compare(left=test.left, ops=[inv[op_type]()],
                              comparators=test.comparators)
    if isinstance(test, ast.BoolOp):
        new_op = ast.Or() if isinstance(test.op, ast.And) else ast.And()
        return ast.BoolOp(op=new_op, values=[_negate_test(v) for v in test.values])
    return ast.UnaryOp(op=ast.Not(), operand=test)


class _BranchInverter(ast.NodeTransformer):
    def __init__(self, rng: random.Random):
        self.rng = rng

    def visit_If(self, node: ast.If) -> ast.If:
        self.generic_visit(node)
        if node.orelse and self.rng.random() < 0.5:
            node.test = _negate_test(node.test)
            node.body, node.orelse = node.orelse, node.body
        return node


class _WhileRewriter(ast.NodeTransformer):
    def __init__(self, rng: random.Random):
        self.rng = rng

    def visit_While(self, node: ast.While) -> ast.While:
        self.generic_visit(node)
        if node.orelse or self.rng.random() >= 0.5:
            return node
        check = ast.If(test=_negate_test(node.test), body=[ast.Break()], orelse=[])
        ast.copy_location(check, node)
        node.test = ast.Constant(value=True)
        node.body = [check] + node.body
        return node


class _Flattener:
    """Split a statement list into state blocks."""

    def __init__(self, rng: random.Random):
        self.blocks: dict[int, list[ast.stmt]] = {}
        self.next_id = 0
        self.rng = rng

    def new_state(self) -> int:
        sid = self.next_id
        self.next_id += 1
        return sid

    @staticmethod
    def _assign(state: int) -> ast.Assign:
        return ast.Assign(
            targets=[ast.Name(id=_STATE_VAR, ctx=ast.Store())],
            value=ast.Constant(value=state),
        )

    def flatten_list(self, stmts: list[ast.stmt], cont: int) -> int:
        """Flatten ``stmts``; after the list, go to state ``cont``.

        Returns the starting state. ``cont`` is never None (the
        top level uses an exit state that only breaks).
        """
        if not stmts:
            return cont
        start = self.new_state()
        cur = start
        cur_block: list[ast.stmt] = []
        for i, stmt in enumerate(stmts):
            is_last = i == len(stmts) - 1
            if isinstance(stmt, ast.If):
                cond = self.new_state()
                self.blocks[cur] = cur_block + [self._assign(cond)]
                after = cont if is_last else self.new_state()
                then_start = self.flatten_list(stmt.body, after)
                else_start = (
                    self.flatten_list(stmt.orelse, after) if stmt.orelse else after
                )
                self.blocks[cond] = [
                    ast.If(
                        test=stmt.test,
                        body=[self._assign(then_start)],
                        orelse=[self._assign(else_start)],
                    )
                ]
                cur = after
                cur_block = []
            elif isinstance(stmt, ast.Return):
                cur_block.append(stmt)
                self.blocks[cur] = cur_block
                # statements after a Return are dead in the original
                # too; keep them in a state nobody jumps to.
                cur = self.new_state()
                cur_block = []
            else:
                cur_block.append(stmt)
        if cur_block:
            self.blocks[cur] = cur_block + [self._assign(cont)]
        # an empty cur_block means cur is either the continuation
        # state (owned by the caller) or a dead state after a Return;
        # either way there is nothing to define for it here.
        return start


def _can_flatten(func: ast.FunctionDef) -> bool:
    body = func.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    if len(body) < 2 and not any(isinstance(s, ast.If) for s in body):
        return False
    # only this function's own scope: do not descend into nested
    # functions, classes or lambdas (their yield/global belong to
    # them, not to this function).
    stack = list(func.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.Yield, ast.YieldFrom, ast.Global, ast.Nonlocal)):
            return False
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(ast.iter_child_nodes(node))
    return True


def flatten_function(func: ast.FunctionDef, rng: random.Random) -> bool:
    """Replace ``func``'s body with a state-machine dispatcher."""
    if not _can_flatten(func):
        return False
    fl = _Flattener(rng)
    exit_state = fl.new_state()
    fl.blocks[exit_state] = [ast.Break()]
    start = fl.flatten_list(func.body, exit_state)
    states = list(fl.blocks.keys())
    rng.shuffle(states)
    chain: list[ast.stmt] = [ast.Break()]
    for state in reversed(states):
        test = ast.Compare(
            left=ast.Name(id=_STATE_VAR, ctx=ast.Load()),
            ops=[ast.Eq()],
            comparators=[ast.Constant(value=state)],
        )
        chain = [ast.If(test=test, body=fl.blocks[state], orelse=chain)]
    func.body = [
        ast.Assign(
            targets=[ast.Name(id=_STATE_VAR, ctx=ast.Store())],
            value=ast.Constant(value=start),
        ),
        ast.While(test=ast.Constant(value=True), body=chain, orelse=[]),
    ]
    ast.fix_missing_locations(func)
    return True


def apply_controlflow(tree: ast.Module, seed: str, module: str) -> int:
    """Apply branch inversion, while rewriting and flattening.

    Returns the number of functions flattened. Branch inversion and
    while rewriting are applied to every function (including nested
    ones and methods); flattening is applied to every FunctionDef
    whose body qualifies.
    """
    rng = random.Random(int(hashlib.sha256(
        f"{seed}\x00{module}\x00cf".encode()).hexdigest()[:8], 16))
    funcs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    tree = _BranchInverter(rng).visit(tree)
    tree = _WhileRewriter(rng).visit(tree)
    ast.fix_missing_locations(tree)
    count = 0
    for func in funcs:
        # effective body ignoring a leading docstring: a single Return
        # (e.g. a VM stub, whose body is [docstring?, Return]) is not
        # worth flattening.
        body = func.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body = body[1:]
        if len(body) <= 1:
            continue
        if flatten_function(func, rng):
            count += 1
    return count
