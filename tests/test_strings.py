import unittest

from pyobf.strings import (
    decrypt_str,
    derive_key,
    derive_master,
    encrypt_str,
    encrypt_str_indexed,
    helper_name_for,
    helper_source,
)


class TestStrings(unittest.TestCase):
    def test_roundtrip(self):
        master = derive_master("42")
        for s in ["hello", "total:", "你好世界", "a" * 100, '{"k": 1}']:
            self.assertEqual(decrypt_str(encrypt_str(s, master), master), s)

    def test_per_string_salt_differs(self):
        # Same plaintext, different occurrence index -> different payload,
        # and neither payload contains the plaintext.
        master = derive_master("42")
        a = encrypt_str_indexed("hello", master, "42", "m", 0)
        b = encrypt_str_indexed("hello", master, "42", "m", 1)
        self.assertNotEqual(a, b)
        self.assertNotIn("hello", a)
        self.assertEqual(decrypt_str(a, master), "hello")
        self.assertEqual(decrypt_str(b, master), "hello")

    def test_different_seed_different_cipher(self):
        self.assertNotEqual(
            encrypt_str("hello", derive_master("1")),
            encrypt_str("hello", derive_master("2")),
        )

    def test_helper_name_varies_per_module(self):
        self.assertNotEqual(helper_name_for("1", "a"), helper_name_for("1", "b"))
        self.assertEqual(helper_name_for("1", "a"), helper_name_for("1", "a"))
        self.assertNotIn(helper_name_for("1", "a"), ("_pyobf_s",))

    def test_helper_source_runs(self):
        master = derive_master("7")
        helper = helper_name_for("7", "m")
        ns: dict = {}
        exec(helper_source(helper, master), ns)
        enc = encrypt_str_indexed("secret-value", master, "7", "m", 3)
        self.assertEqual(ns[helper](enc), "secret-value")
        # master is embedded as bytes([...]), not as a hex string
        self.assertNotIn(master.hex(), helper_source(helper, master))

    def test_derive_key_backcompat(self):
        # Old callers passing derive_key() as the master still round-trip.
        key = derive_key("42")
        self.assertEqual(decrypt_str(encrypt_str("hello", key), key), "hello")


if __name__ == "__main__":
    unittest.main()
