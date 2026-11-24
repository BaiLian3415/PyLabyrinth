import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pyobf.obfuscator import ObfuscateError, obfuscate_project


def run_py(path: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(path)], capture_output=True, text=True, timeout=10)


def write(tmp: Path, name: str, src: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return p


class TestTransform(unittest.TestCase):
    def test_hello_output_identical(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "hello.py", '''import math\n\ndef calc(prices):\n    total = sum(prices)\n    return total * 2\n\nprint(calc([1, 2, 3]))\nprint("done", math.sqrt(4))\n''')
            out = tmp / "out"
            obfuscate_project(input_path=src, output_path=out / "hello.py", seed="42", level=2)
            res = run_py(out / "hello.py")
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout, "12\ndone 2.0\n")

    def test_builtins_attributes_imports_untouched(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "a.py", '''import os\nx = [3, 1, 2]\nprint(len(x), sorted(x))\nprint(os.path.join("a", "b"))\nclass C:\n    def method(self):\n        return self.attr\n''')
            out = tmp / "out.py"
            obfuscate_project(input_path=src, output_path=out, seed="1", level=2)
            text = out.read_text(encoding="utf-8")
            self.assertIn("len(", text)
            self.assertIn("sorted(", text)
            self.assertIn("os.path.join", text)
            self.assertIn(".attr", text)
            self.assertIn("def method(self)", text)

    def test_closure_global_nonlocal_match_walrus(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "a.py", '''count = 0\ndef bump():\n    global count\n    count += 1\n    return count\ndef outer():\n    x = 10\n    def inner():\n        return x + 1\n    return inner()\nif (n := 5) > 3:\n    print("walrus", n)\nmatch n:\n    case 5:\n        print("five")\nprint(bump(), bump(), outer())\n''')
            out = tmp / "out.py"
            obfuscate_project(input_path=src, output_path=out, seed="5", level=2)
            res = run_py(out)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout, "walrus 5\nfive\n1 2 11\n")

    def test_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "a.py", "def f():\n    secret = 1\n    return secret\nprint(f())\n")
            o1, o2 = tmp / "o1.py", tmp / "o2.py"
            obfuscate_project(input_path=src, output_path=o1, seed="42", level=2)
            obfuscate_project(input_path=src, output_path=o2, seed="42", level=2)
            self.assertEqual(o1.read_text(), o2.read_text())

    def test_cross_file_private_import(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            srcdir = tmp / "src"
            write(srcdir, "helper.py", "def _helper(x):\n    return x * 2\ndef public(x):\n    return _helper(x) + 1\n")
            write(srcdir, "main.py", "from helper import _helper, public\nimport helper\nprint(public(10), _helper(5), helper._helper(3))\n")
            out = tmp / "out"
            obfuscate_project(input_path=srcdir, output_path=out, seed="99", level=2)
            res = subprocess.run([sys.executable, "main.py"], cwd=out, capture_output=True, text=True, timeout=10)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.strip(), "21 10 6")

    def test_rename_args_keyword_call(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "a.py", 'def greet(name, greeting="hi"):\n    return f"{greeting}, {name}"\nprint(greet(name="Bob", greeting="hey"))\n')
            out = tmp / "out.py"
            obfuscate_project(input_path=src, output_path=out, seed="9", level=1, rename_args=True)
            res = run_py(out)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.strip(), "hey, Bob")

    def test_syntax_error_raises(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "bad.py", "def broken(:\n")
            with self.assertRaises(ObfuscateError):
                obfuscate_project(input_path=src, output_path=tmp / "o.py", seed="1", level=1)

    def test_int_obfuscation_output_identical(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "a.py", "print(100 + 250)\nprint(-42)\nprint([1, 2, 3][0])\n")
            out = tmp / "out.py"
            obfuscate_project(input_path=src, output_path=out, seed="42", level=2)
            text = out.read_text(encoding="utf-8")
            self.assertNotIn("100 + 250", text)
            res = run_py(out)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout, "350\n-42\n1\n")

    def test_match_pattern_ints_untouched(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "a.py", "n = 100\nmatch n:\n    case 100:\n        print('hundred')\n    case _:\n        print('other')\n")
            out = tmp / "out.py"
            obfuscate_project(input_path=src, output_path=out, seed="42", level=2)
            text = out.read_text(encoding="utf-8")
            self.assertIn("case 100:", text)
            res = run_py(out)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.strip(), "hundred")

    def test_no_fixed_helper_name(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "a.py", 'print("hello world")\n')
            out = tmp / "out.py"
            obfuscate_project(input_path=src, output_path=out, seed="42", level=2)
            text = out.read_text(encoding="utf-8")
            self.assertNotIn("_pyobf_s", text)
            self.assertNotIn("hello world", text)
            res = run_py(out)
            self.assertEqual(res.stdout.strip(), "hello world")

    def test_private_module_var_cross_file(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            srcdir = tmp / "src"
            write(srcdir, "cfg.py", "_FACTOR = 10\ndef get():\n    return _FACTOR\n")
            write(srcdir, "main.py", "from cfg import _FACTOR\nimport cfg\nprint(_FACTOR, cfg._FACTOR, cfg.get())\n")
            out = tmp / "out"
            obfuscate_project(input_path=srcdir, output_path=out, seed="99", level=2)
            res = subprocess.run([sys.executable, "main.py"], cwd=out, capture_output=True, text=True, timeout=10)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.strip(), "10 10 10")

    def test_private_attrs_renamed(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "a.py", '''class C:\n    _limit = 3\n    def __init__(self):\n        self._count = 0\n    def _bump(self):\n        self._count += 1\n        return self._count\n    def get(self):\n        return self._bump() + self._limit\nprint(C().get())\n''')
            out = tmp / "out.py"
            obfuscate_project(input_path=src, output_path=out, seed="42", level=2)
            text = out.read_text(encoding="utf-8")
            self.assertNotIn("_count", text)
            self.assertNotIn("_bump", text)
            self.assertNotIn("_limit", text)
            res = run_py(out)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.strip(), "4")

    def test_external_private_attr_not_renamed(self):
        # Documented limit: obj._x where obj is not self/cls is left alone.
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "a.py", "class C:\n    def __init__(self):\n        self._x = 5\nc = C()\nprint(c._x)\n")
            out = tmp / "out.py"
            obfuscate_project(input_path=src, output_path=out, seed="42", level=2)
            text = out.read_text(encoding="utf-8")
            self.assertIn("c._x", text)

    def test_bytes_encrypted(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "a.py", 'print(b"hello-bytes")\n')
            out = tmp / "out.py"
            obfuscate_project(input_path=src, output_path=out, seed="42", level=2)
            text = out.read_text(encoding="utf-8")
            self.assertNotIn("hello-bytes", text)
            res = run_py(out)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.strip(), "b'hello-bytes'")

    def test_long_string_split(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "a.py", 'print("abcdefghijklmnopqrstuvwxyz0123456789")\n')
            out = tmp / "out.py"
            obfuscate_project(input_path=src, output_path=out, seed="42", level=2)
            text = out.read_text(encoding="utf-8")
            self.assertNotIn("abcdefghijklmnopqrstuvwxyz", text)
            res = run_py(out)
            self.assertEqual(res.stdout.strip(), "abcdefghijklmnopqrstuvwxyz0123456789")

    def test_int_not_in_compiled_consts(self):
        # Alpha.3: len()-based form must not constant-fold back to the
        # original int in the compiled code object (recursively).
        import dis

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "a.py", "print(2026 + 100000)\n")
            out = tmp / "out.py"
            obfuscate_project(input_path=src, output_path=out, seed="42", level=2)
            code = compile(out.read_text(encoding="utf-8"), str(out), "exec")
            consts: set = set()

            def collect(c):
                consts.update(c.co_consts)
                for sub in c.co_consts:
                    if hasattr(sub, "co_consts"):
                        collect(sub)

            collect(code)
            self.assertNotIn(2026, consts)
            self.assertNotIn(100000, consts)
            res = run_py(out)
            self.assertEqual(res.stdout.strip(), "102026")

    def test_vmp_function_output_identical(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "a.py", "def calc(a, b):\n    x = a * b + 1\n    if x > 10:\n        return x * 2\n    return x - 1\nprint(calc(3, 4), calc(2, 3))\n")
            out = tmp / "out.py"
            res = obfuscate_project(input_path=src, output_path=out, seed="42", level=3)
            self.assertEqual(res.files[0].vm_functions, 1)
            text = out.read_text(encoding="utf-8")
            self.assertNotIn("a * b + 1", text)
            r = run_py(out)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), "26 6")

    def test_vmp_default_arg_and_private_global(self):
        # default arg still works via the stub; a module-level private
        # constant referenced by the VM'd function resolves under its
        # renamed name.
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "a.py", "_BASE = 100\ndef total(x, k=2):\n    return x * k + _BASE\nprint(total(5), total(5, 3))\n")
            out = tmp / "out.py"
            obfuscate_project(input_path=src, output_path=out, seed="42", level=3)
            r = run_py(out)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), "110 115")

    def test_vmp_cross_file_private_call(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            srcdir = tmp / "src"
            write(srcdir, "helper.py", "def _double(x):\n    return x * 2\n")
            write(srcdir, "main.py", "from helper import _double\nprint(_double(21))\n")
            out = tmp / "out"
            obfuscate_project(input_path=srcdir, output_path=out, seed="42", level=3)
            r = subprocess.run([sys.executable, "main.py"], cwd=out, capture_output=True, text=True, timeout=10)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), "42")

    def test_vmp_off_at_level2(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "a.py", "def f(a):\n    return a + 1\nprint(f(1))\n")
            out = tmp / "out.py"
            res = obfuscate_project(input_path=src, output_path=out, seed="42", level=2)
            self.assertEqual(res.files[0].vm_functions, 0)
            res2 = obfuscate_project(input_path=src, output_path=out, seed="42", level=2, vmp=True)
            self.assertEqual(res2.files[0].vm_functions, 1)

    def test_shuffle_top_defs(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "a.py", "def aaa():\n    return 1\ndef bbb():\n    return 2\ndef ccc():\n    return 3\nprint(aaa(), bbb(), ccc())\n")
            out = tmp / "out.py"
            obfuscate_project(input_path=src, output_path=out, seed="42", level=3)
            text = out.read_text(encoding="utf-8")
            order = [text.index("def aaa"), text.index("def bbb"), text.index("def ccc")]
            self.assertNotEqual(order, sorted(order))
            res = run_py(out)
            self.assertEqual(res.stdout.strip(), "1 2 3")

    def test_level3_opaque_junk_never_runs(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "a.py", "print(12345)\n")
            out = tmp / "out.py"
            obfuscate_project(input_path=src, output_path=out, seed="7", level=3)
            text = out.read_text(encoding="utf-8")
            self.assertNotIn("if False:", text)
            self.assertIn("% 7 ==", text)  # opaque dead branch is present
            res = run_py(out)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.strip(), "12345")

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "a.py", "x = 1\nprint(x)\n")
            out = tmp / "o.py"
            obfuscate_project(input_path=src, output_path=out, seed="1", level=1, dry_run=True)
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
