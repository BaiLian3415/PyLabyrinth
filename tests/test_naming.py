import keyword
import unittest

from pyobf.naming import NameGenerator


class TestNaming(unittest.TestCase):
    def test_deterministic(self):
        a = NameGenerator("42")
        b = NameGenerator("42")
        self.assertEqual(a.generate("foo", "m:f"), b.generate("foo", "m:f"))

    def test_different_seed_or_scope_differs(self):
        a = NameGenerator("42")
        self.assertNotEqual(a.generate("foo", "m:f"), NameGenerator("43").generate("foo", "m:f"))
        self.assertNotEqual(a.generate("foo", "m:f"), a.generate("foo", "m:g"))

    def test_never_keyword_or_builtin(self):
        gen = NameGenerator("1")
        for name in ["foo", "bar", "x", "count", "value"]:
            out = gen.generate(name, "m:f")
            self.assertFalse(keyword.iskeyword(out))
            self.assertNotIn(out, {"print", "len", "list", "str"})

    def test_stable_reuse(self):
        gen = NameGenerator("1")
        self.assertEqual(gen.generate("foo", "m:f"), gen.generate("foo", "m:f"))


if __name__ == "__main__":
    unittest.main()
