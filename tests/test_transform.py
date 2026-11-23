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

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = write(tmp, "a.py", "x = 1\nprint(x)\n")
            out = tmp / "o.py"
            obfuscate_project(input_path=src, output_path=out, seed="1", level=1, dry_run=True)
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
