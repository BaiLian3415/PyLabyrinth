import ast
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pyobf.controlflow import apply_controlflow, flatten_function
from pyobf.obfuscator import obfuscate_project


def run_src(src: str) -> str:
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "m.py"
        p.write_text(src, encoding="utf-8")
        r = subprocess.run([sys.executable, str(p)], capture_output=True, text=True, timeout=10)
        assert r.returncode == 0, r.stderr
        return r.stdout


def cf_src(src: str, seed: str = "42") -> str:
    tree = ast.parse(src)
    apply_controlflow(tree, seed, "m")
    return ast.unparse(tree)


class TestControlFlow(unittest.TestCase):
    def test_flatten_if_return(self):
        src = (
            "def f(a):\n"
            "    x = a * 2\n"
            "    if x > 10:\n"
            "        return x + 1\n"
            "    else:\n"
            "        return x - 1\n"
            "print(f(3), f(7))\n"
        )
        out = cf_src(src)
        self.assertIn("while True", out)
        self.assertEqual(run_src(out), "5 15\n")

    def test_flatten_while_and_for(self):
        src = (
            "def f(n):\n"
            "    t = 0\n"
            "    i = 0\n"
            "    while i < n:\n"
            "        t += i\n"
            "        i += 1\n"
            "    for j in range(3):\n"
            "        t += j\n"
            "    return t\n"
            "print(f(5))\n"
        )
        self.assertEqual(run_src(cf_src(src)), "13\n")

    def test_flatten_return_in_middle(self):
        src = (
            "def f(a):\n"
            "    if a < 0:\n"
            "        return -1\n"
            "    x = a * 3\n"
            "    return x\n"
            "print(f(-5), f(4))\n"
        )
        self.assertEqual(run_src(cf_src(src)), "-1 12\n")

    def test_flatten_nested_if(self):
        src = (
            "def f(a, b):\n"
            "    if a > 0:\n"
            "        if b > 0:\n"
            "            return 1\n"
            "        return 2\n"
            "    return 3\n"
            "print(f(1, 1), f(1, -1), f(-1, 1))\n"
        )
        self.assertEqual(run_src(cf_src(src)), "1 2 3\n")

    def test_generator_and_global_not_flattened(self):
        src = (
            "def gen(n):\n"
            "    i = 0\n"
            "    while i < n:\n"
            "        yield i\n"
            "        i += 1\n"
            "print(list(gen(3)))\n"
        )
        tree = ast.parse(src)
        func = tree.body[0]
        self.assertFalse(flatten_function(func, __import__("random").Random(1)))
        src2 = (
            "_G = 0\n"
            "def f():\n"
            "    global _G\n"
            "    _G = 1\n"
            "    return _G\n"
            "print(f())\n"
        )
        tree2 = ast.parse(src2)
        self.assertFalse(flatten_function(tree2.body[1], __import__("random").Random(1)))

    def test_end_to_end_cf(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = tmp / "a.py"
            src.write_text(
                "def calc(a, b):\n"
                "    x = a * b + 1\n"
                "    if x > 10:\n"
                "        return x * 2\n"
                "    return x - 1\n"
                "print(calc(3, 4), calc(2, 3))\n",
                encoding="utf-8",
            )
            out = tmp / "out.py"
            # VMP off so the function is flattened instead of VM'd
            res = obfuscate_project(input_path=src, output_path=out, seed="42", level=3, vmp=False)
            self.assertGreater(res.files[0].cf_functions, 0)
            r = subprocess.run([sys.executable, str(out)], capture_output=True, text=True, timeout=10)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), "26 6")
            # VMP on: the same function is VM'd, not flattened
            res_vm = obfuscate_project(input_path=src, output_path=out, seed="42", level=3)
            self.assertEqual(res_vm.files[0].vm_functions, 1)
            self.assertEqual(res_vm.files[0].cf_functions, 0)
            # level 2: no control-flow obfuscation by default
            res2 = obfuscate_project(input_path=src, output_path=out, seed="42", level=2)
            self.assertEqual(res2.files[0].cf_functions, 0)
            # explicit opt-out at level 3
            res3 = obfuscate_project(input_path=src, output_path=out, seed="42", level=3, cf=False)
            self.assertEqual(res3.files[0].cf_functions, 0)


if __name__ == "__main__":
    unittest.main()
