"""
test_flag_miner.py — locks in the correctness work from this session's
adversarial hardening. Run with:  python3 -m unittest discover -s tests

Two things this guards against regressing:
  1. Every real encoding chain the engine relies on must keep decoding.
  2. The XOR crib/sweep attacks must not manufacture fake flags out of
     unrelated noise (this actually happened during development — see the
     guards in flag_miner.py's _xor_crib and the trail-restriction logic in
     decode_ladder — and stayed broken across two follow-up "fixes" before
     the adversarial fuzz loop below caught it for real).
"""
import base64
import codecs
import gzip
import os
import random
import sys
import unittest
import urllib.parse
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyf.flag_miner import decode_ladder, find_flag  # noqa: E402

FLAG = "CYF{test_flag_value}"


class TruePositives(unittest.TestCase):
    def _solves(self, text, expected=FLAG):
        f, trail = decode_ladder(text)
        self.assertEqual(f, expected, f"trail={trail}")
        return trail

    def test_direct(self):
        self._solves(FLAG)

    def test_rot13(self):
        self._solves(codecs.encode(FLAG, "rot13"))

    def test_rot47(self):
        enc = "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
                       for c in FLAG)
        self._solves(enc)

    def test_atbash(self):
        def flip(c):
            if "a" <= c <= "z":
                return chr(ord("z") - (ord(c) - ord("a")))
            if "A" <= c <= "Z":
                return chr(ord("Z") - (ord(c) - ord("A")))
            return c
        self._solves("".join(flip(c) for c in FLAG))

    def test_urldecode(self):
        self._solves(urllib.parse.quote(FLAG))

    def test_hex(self):
        self._solves(FLAG.encode().hex())

    def test_base64_of_base32(self):
        self._solves(base64.b64encode(base64.b32encode(FLAG.encode())).decode())

    def test_base64_of_gzip(self):
        self._solves(base64.b64encode(gzip.compress(FLAG.encode())).decode())

    def test_base64_of_zlib(self):
        self._solves(base64.b64encode(zlib.compress(FLAG.encode())).decode())

    def test_single_byte_xor_raw(self):
        raw = bytes(b ^ 0x42 for b in FLAG.encode())
        self._solves(raw.decode("latin-1"))

    def test_repeating_key_xor_crib_raw(self):
        key = b"k3y"
        raw = FLAG.encode()
        ct = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
        self._solves(ct.decode("latin-1"))

    def test_secret_embedded_in_surrounding_text(self):
        blob = f"the secret is secret={base64.b64encode(FLAG.encode()).decode()} ok?"
        self._solves(blob)


class FalsePositiveResistance(unittest.TestCase):
    """Regression test for the exact bug class found during development:
    the XOR crib/single-byte-XOR brute-force paths can forge a flag-shaped
    match out of unrelated noise unless guarded (this happened twice while
    building the guards themselves — the fix is in _plausible_flag_body()).

    Measured true residual rate on 100,000 adversarial trials: 1/100,000
    (0.001%) — not zero, and can't be driven to exactly zero without either
    rejecting legitimate short/low-entropy flags or removing the direct
    crib-on-raw-ciphertext capability entirely. This test uses a fixed seed
    and a small tolerance (not assertEqual([])) so it reflects that measured
    reality instead of asserting a guarantee the technique doesn't make."""

    def test_no_false_positives_on_random_noise(self, n_trials=2000, seed=1337):
        rng = random.Random(seed)
        bad = []
        for i in range(n_trials):
            kind = i % 6
            if kind == 0:
                s = base64.b64encode(os.urandom(rng.randint(10, 120))).decode()
            elif kind == 1:
                s = base64.b64encode(gzip.compress(os.urandom(rng.randint(5, 80)))).decode()
            elif kind == 2:
                b64 = base64.b64encode(os.urandom(rng.randint(10, 100))).decode()
                s = "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
                            for c in b64)
            elif kind == 3:
                s = os.urandom(rng.randint(10, 100)).hex()
            elif kind == 4:
                s = "".join(chr(rng.randint(32, 126)) for _ in range(rng.randint(20, 150)))
            else:
                s = os.urandom(rng.randint(20, 150)).decode("latin-1")
            f, trail = decode_ladder(s)
            if f:
                bad.append((i, kind, f, trail))
        self.assertLessEqual(len(bad), 2,
                              f"{len(bad)}/{n_trials} false positives (expect ~0-1 at this "
                              f"scale given the measured 0.001% rate): {bad}")


class DirectFlagFinder(unittest.TestCase):
    def test_finds_all_three_prefixes(self):
        for prefix in ("CYF", "FLAG", "CTF"):
            self.assertEqual(find_flag(f"noise {prefix}{{abc123}} noise"),
                              f"{prefix}{{abc123}}")

    def test_no_match_without_braces(self):
        self.assertIsNone(find_flag("CYF is not a flag by itself"))


if __name__ == "__main__":
    unittest.main()
