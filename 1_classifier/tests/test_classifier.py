"""
test_classifier.py — locks in the rule-engine keyword coverage from this
session's widening pass. Two things this guards against regressing:
  1. Every training-set example must still resolve to its correct category
     via the rule engine alone (or safely defer to ML — never resolve
     confidently to the WRONG category).
  2. A held-out set of phrasings NOT in the training data — this is what
     actually caught two real keyword collisions during development (the
     naive fix for one miss silently broke a different, previously-passing
     case) that a training-set-only check would have missed entirely.

Run with:  python3 -m unittest discover -s tests
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from classifier import rule_scan, _starter_dataset  # noqa: E402

# Deliberately NOT phrased like anything in _starter_dataset() — different
# vocabulary, different sentence shape, per category.
HELD_OUT = [
    ("the vault uses a broken PRNG to generate its encryption nonce", "crypto"),
    ("cross site scripting in the comment box lets you steal cookies", "web"),
    ("double free bug in the allocator gives arbitrary write", "pwn"),
    ("write a fake vtable to hijack control flow in this cpp binary", "pwn"),
    ("unpack this obfuscated javascript to find the check", "reverse"),
    ("carve a hidden partition out of this disk image", "forensics"),
    ("hide a message using the DCT coefficients of a jpeg", "stego"),
    ("find the hotel where this vacation photo was taken", "osint"),
    ("extract firmware from an old router and find the backdoor", "hardware"),
]


class RuleEngineTrainingSetRegression(unittest.TestCase):
    def test_never_confidently_wrong_on_training_set(self):
        wrong = []
        for text, expected in _starter_dataset():
            r = rule_scan(text=text)
            if r and r.category != expected:
                wrong.append((expected, r.category, text))
        self.assertEqual(wrong, [], f"rule engine confidently wrong on: {wrong}")


class RuleEngineHeldOutPhrasing(unittest.TestCase):
    def test_resolves_held_out_phrasing_correctly(self):
        wrong = []
        for text, expected in HELD_OUT:
            r = rule_scan(text=text)
            got = r.category if r else None
            if got != expected:
                wrong.append((expected, got, text))
        self.assertEqual(wrong, [], f"rule engine missed/wrong on held-out phrasing: {wrong}")


if __name__ == "__main__":
    unittest.main()
