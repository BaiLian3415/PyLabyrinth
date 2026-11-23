import unittest

from pyobf.strings import decrypt_str, derive_key, encrypt_str, helper_source


class TestStrings(unittest.TestCase):
    def test_roundtrip(self):
        key = derive_key("42")
        for s in ["hello", "total:", "你好世界", "a" * 100, '{"k": 1}']:
            self.assertEqual(decrypt_str(encrypt_str(s, key), key), s)

    def test_different_seed_different_cipher(self):
        self.assertNotEqual(
            encrypt_str("hello", derive_key("1")),
            encrypt_str("hello", derive_key("2")),
        )

    def test_helper_source_runs(self):
        key = derive_key("7")
        ns: dict = {}
        exec(helper_source("_pyobf_s", key), ns)
        enc = encrypt_str("secret-value", key)
        self.assertEqual(ns["_pyobf_s"](enc), "secret-value")


if __name__ == "__main__":
    unittest.main()
