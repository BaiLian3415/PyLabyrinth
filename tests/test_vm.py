import ast
import base64
import unittest

from pyobf.vm import (
    _Compiler,
    _xor_stream,
    apply_vmp,
    executor_source,
    key_for,
    perm_for,
)


def run_vm_src(src: str, func_name: str, args, globs=None):
    # full alpha.6 path: per-file perm + sealed payload
    perm = perm_for("42", "m")
    key_int = key_for("42", "m")
    tree = ast.parse(src)
    func = next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == func_name
    )
    payload = _Compiler(func, {}, {}, set(), perm=perm, key_int=key_int,
                        seed="42", module="m").compile()
    ns: dict = {}
    exec(executor_source("_vm_exec", perm, key_int), ns)
    g = dict(globals())
    g.update(globs or {})
    return ns["_vm_exec"](base64.b64encode(payload).decode(), args, g)


class TestVM(unittest.TestCase):
    def test_arithmetic_if(self):
        src = "def f(a, b):\n    x = a * b + 1\n    if x > 10:\n        return x * 2\n    return x - 1\n"
        self.assertEqual(run_vm_src(src, "f", (3, 4)), 26)
        self.assertEqual(run_vm_src(src, "f", (2, 3)), 6)

    def test_while_break(self):
        src = "def f(n):\n    t = 0\n    i = 0\n    while True:\n        if i >= n:\n            break\n        t += i\n        i += 1\n    return t\n"
        self.assertEqual(run_vm_src(src, "f", (5,)), 10)

    def test_for_list_subscript(self):
        src = "def f(n):\n    a = [10, 20, 30]\n    s = 0\n    for i in range(n):\n        s += a[i]\n    return s\n"
        self.assertEqual(run_vm_src(src, "f", (3,)), 60)

    def test_boolop_and_or(self):
        src = "def f(a, b):\n    return (a > 1 and b < 10) or not a\n"
        self.assertTrue(run_vm_src(src, "f", (2, 5)))
        self.assertTrue(run_vm_src(src, "f", (0, 5)))
        self.assertFalse(run_vm_src(src, "f", (2, 99)))

    def test_tuple_unpack_slice_ifexp(self):
        src = "def f(s):\n    a, b = s[0:2]\n    return a + b if len(s) > 1 else 'x'\n"
        self.assertEqual(run_vm_src(src, "f", ("hi",)), "hi")

    def test_calls_and_globals(self):
        src = "def f(x):\n    return len(x) + sum(x)\n"
        self.assertEqual(run_vm_src(src, "f", ([1, 2, 3],)), 9)  # 3 + 6

    def test_continue_augassign_subscript(self):
        src = "def f(xs):\n    t = 0\n    for x in xs:\n        if x == 2:\n            continue\n        t += x\n    return t\n"
        self.assertEqual(run_vm_src(src, "f", ([1, 2, 3],)), 4)
        src2 = "def f(a):\n    a[0] += 5\n    return a[0]\n"
        self.assertEqual(run_vm_src(src2, "f", ([10],)), 15)

    def test_in_notin_attr(self):
        src = "def f(a):\n    return 2 in a and 9 not in a\n"
        self.assertTrue(run_vm_src(src, "f", ([1, 2, 3],)))
        obj = type("O", (), {})()
        src2 = "def f(o):\n    o.x = 7\n    return o.x * 2\n"
        self.assertEqual(run_vm_src(src2, "f", (obj,)), 14)

    def test_payload_is_sealed_and_permuted(self):
        # alpha.6: the base64 payload must not parse as a plain payload
        # (XOR + checksum), and different seeds must permute opcodes.
        src = "def f(a, b):\n    return a + b\n"
        tree = ast.parse(src)
        func = tree.body[0]
        perm = perm_for("42", "m")
        key_int = key_for("42", "m")
        payload = _Compiler(func, {}, {}, set(), perm=perm, key_int=key_int,
                            seed="42", module="m").compile()
        raw = payload  # compile() returns sealed bytes, not base64
        # sealed bytes must not parse as a plain payload: the header
        # only becomes sane after XOR-decrypting and stripping the
        # 4-byte checksum
        import struct
        plain = _xor_stream(raw, key_int)
        n, c, _l = struct.unpack(">HHH", plain[4:10])
        self.assertGreater(n, 0)
        self.assertGreaterEqual(c, 0)
        self.assertEqual((n, c, _l), struct.unpack(">HHH", plain[4:10]))
        garbage = struct.unpack(">HHH", raw[4:10])
        self.assertNotEqual(garbage, (n, c, _l))
        self.assertNotEqual(perm_for("42", "m"), perm_for("43", "m"))
        self.assertNotEqual(perm, list(range(26)))
        # tampering is detected by the checksum
        ns: dict = {}
        exec(executor_source("_vm_exec", perm, key_int), ns)
        bad = bytearray(raw)
        bad[10] ^= 0xFF
        with self.assertRaises(ValueError):
            ns["_vm_exec"](base64.b64encode(bytes(bad)).decode(), (1, 2), {})

    def test_nops_present(self):
        src = "def f(n):\n    t = 0\n    for i in range(n):\n        t += i\n    return t\n"
        tree = ast.parse(src)
        func = tree.body[0]
        comp = _Compiler(func, {}, {}, set(), seed="42", module="m")
        comp.compile()
        from pyobf.vm import OP_NOP
        self.assertGreater(sum(1 for op, _ in comp.code if op == OP_NOP), 0)

    def test_apply_vmp_rejects_unsupported(self):
        # try/except, comprehension, nested def: left alone, count 0
        src = (
            "def f(x):\n"
            "    try:\n"
            "        return x + 1\n"
            "    except Exception:\n"
            "        return 0\n"
            "def g(x):\n"
            "    return [i * 2 for i in x]\n"
            "def h(x):\n"
            "    def inner(y):\n"
            "        return y + 1\n"
            "    return inner(x)\n"
        )
        tree = ast.parse(src)
        count, name, _perm, _key = apply_vmp(tree, "1", "m", {}, {}, set())
        self.assertEqual(count, 0)
        self.assertIsNone(name)
        self.assertEqual(len(tree.body), 3)

    def test_apply_vmp_accepts_simple(self):
        src = "def f(a, b):\n    return a + b\n"
        tree = ast.parse(src)
        count, name, _perm, _key = apply_vmp(tree, "1", "m", {}, {}, set())
        self.assertEqual(count, 1)
        self.assertIsNotNone(name)
        # stub keeps the name and a single return
        stub = tree.body[0]
        self.assertEqual(stub.name, "f")
        self.assertEqual(len(stub.body), 1)
        self.assertIsInstance(stub.body[0], ast.Return)


if __name__ == "__main__":
    unittest.main()
