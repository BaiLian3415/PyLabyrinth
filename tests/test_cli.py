import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def cli(*args, cwd=None):
    return subprocess.run(
        [sys.executable, "-m", "pyobf", *args],
        cwd=cwd or ROOT, capture_output=True, text=True, timeout=15,
    )


class TestCLI(unittest.TestCase):
    def test_help_and_version(self):
        self.assertEqual(cli("--help").returncode, 0)
        self.assertIn("0.1.0-alpha.6", cli("--version").stdout)

    def test_direct_script_entry(self):
        # Regression: `python pyobf/cli.py` and `cd pyobf && python cli.py`
        # used to fail with "attempted relative import with no known
        # parent package". Both must work, as must `python -m pyobf`.
        r1 = subprocess.run(
            [sys.executable, "pyobf/cli.py", "--version"],
            cwd=ROOT, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(r1.returncode, 0, r1.stderr)
        self.assertIn("0.1.0-alpha.6", r1.stdout)
        r2 = subprocess.run(
            [sys.executable, "cli.py", "--version"],
            cwd=ROOT / "pyobf", capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertIn("0.1.0-alpha.6", r2.stdout)

    def test_missing_input(self):
        self.assertEqual(cli("-i", "no-such-file.py", "-o", "x.py").returncode, 2)

    def test_end_to_end_level1(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = tmp / "a.py"
            src.write_text('def f():\n    secret = 42\n    return secret\nprint(f())\n', encoding="utf-8")
            out = tmp / "o.py"
            r = cli("-i", str(src), "-o", str(out), "--seed", "3", "--level", "1")
            self.assertEqual(r.returncode, 0, r.stderr)
            res = subprocess.run([sys.executable, str(out)], capture_output=True, text=True, timeout=10)
            self.assertEqual(res.stdout.strip(), "42")

    def test_output_guard_without_force(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            src = tmp / "a.py"
            src.write_text("print(1)\n", encoding="utf-8")
            outdir = tmp / "out"
            outdir.mkdir()
            (outdir / "a.py").write_text("print(1)\n", encoding="utf-8")
            # directory input to a non-empty dir must be refused without --force
            srcdir = tmp / "src"
            srcdir.mkdir()
            (srcdir / "a.py").write_text("print(1)\n", encoding="utf-8")
            r2 = cli("-i", str(srcdir), "-o", str(outdir))
            self.assertEqual(r2.returncode, 2)


if __name__ == "__main__":
    unittest.main()
