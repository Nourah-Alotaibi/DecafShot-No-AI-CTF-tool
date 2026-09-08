"""
test_scraper.py — unit tests for scrape_ctf_writeups.py's pure logic (title
parsing, snippet cleaning). No network calls — those parts of the scraper
aren't unit-tested here since they depend on live GitHub content; this
locks in the label-extraction logic, which is the part that determines
whether scraped data is even correctly labeled.

Run with: python3 -m unittest discover -s tests
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scrape_ctf_writeups import _category_from_title, _clean_snippet  # noqa: E402


class CategoryFromTitle(unittest.TestCase):
    def test_simple_category(self):
        self.assertEqual(
            _category_from_title("# dyrpto (crypto, 250p, 66 solved)\n\ntext..."),
            "crypto",
        )

    def test_multi_category_takes_first_recognized(self):
        self.assertEqual(
            _category_from_title("# Haystack (crypto/forensics/re, 401p, 8 solved)"),
            "crypto",
        )

    def test_slash_variant(self):
        self.assertEqual(
            _category_from_title("# barcoder (forensics/101, 51p, 37 solved)"),
            "forensics",
        )

    def test_synonym_pwnable(self):
        self.assertEqual(
            _category_from_title("# baby (pwnable, 100p)"),
            "pwn",
        )

    def test_no_parenthetical_returns_none(self):
        self.assertIsNone(_category_from_title("# just a title with no metadata"))

    def test_unrecognized_category_returns_none(self):
        self.assertIsNone(_category_from_title("# mystery (warmup, 500 pts)"))

    def test_only_matches_title_line_not_body(self):
        # a category-looking word later in the body must not be picked up
        # as if it were the title's own parenthetical
        text = "# no category here\n\nThis is actually a (crypto) challenge though."
        self.assertIsNone(_category_from_title(text))


class CleanSnippet(unittest.TestCase):
    def test_strips_code_fences(self):
        text = "intro text\n```python\nprint('secret')\n```\nmore text"
        out = _clean_snippet(text)
        self.assertNotIn("print", out)
        self.assertIn("intro text", out)
        self.assertIn("more text", out)

    def test_strips_images_keeps_link_text(self):
        text = "see ![alt](img.png) and [the writeup](http://example.com)"
        out = _clean_snippet(text)
        self.assertNotIn("img.png", out)
        self.assertIn("the writeup", out)
        self.assertNotIn("example.com", out)

    def test_truncates_to_max_chars(self):
        out = _clean_snippet("word " * 1000, max_chars=50)
        self.assertLessEqual(len(out), 50)

    def test_collapses_whitespace(self):
        out = _clean_snippet("a   b\n\n\nc")
        self.assertEqual(out, "a b c")


if __name__ == "__main__":
    unittest.main()
