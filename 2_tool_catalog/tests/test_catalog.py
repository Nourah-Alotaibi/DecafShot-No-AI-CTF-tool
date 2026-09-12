"""Offline collector coverage; no live GitHub API dependency."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import collect_tools as c


class CatalogTests(unittest.TestCase):
    def test_generative_tools_are_excluded(self):
        for description in ("Use LLMs to hide messages", "OpenAI security assistant", "generative AI solver", "Anthropic-Cybersecurity-Skills"):
            self.assertTrue(c.is_denied({"name": "tool", "description": description}))
        catalog = json.loads((ROOT / "tools_catalog.json").read_text())
        for block in catalog.values():
            for row in block["tools"] + block["meta_lists"]:
                self.assertFalse(c.is_denied(row), row["name"])

    def test_ranking_filtering_and_deduplication(self):
        def repo(name, description="security tool", stars=100):
            return dict(name=name, full_name="lab/" + name, html_url="https://example.test/" + name,
                        description=description, stargazers_count=stars, pushed_at="2026-01-01T00:00:00Z")
        items = [repo("tool"), repo("tool"), repo("awesome-security"), repo("weather", "weather app"), repo("gpt4free")]
        with patch.object(c, "QUERIES", {"web": ["a"], "crypto": ["b"]}), patch.object(c, "CANONICAL", {}), patch.object(c, "gh_search", return_value=(items, "99")), patch.object(c.time, "sleep"):
            result = c.collect()
        self.assertEqual([t["name"] for t in result["web"]["tools"]], ["tool"])
        self.assertEqual(result["crypto"]["tools"], [])
        self.assertEqual(result["web"]["meta_lists"][0]["name"], "awesome-security")

    def test_default_output_matches_engine_input(self):
        sys.path.insert(0, str(ROOT.parent / "3_flag_hunter"))
        from cyf.catalog import CATALOG_PATH
        with patch.object(sys, "argv", ["collect_tools.py"]), patch.object(c, "collect", return_value={}), patch.object(c, "write_outputs") as write:
            c.main()
        self.assertEqual(write.call_args.args[1] / "tools_catalog.json", CATALOG_PATH)

    def test_output_can_be_read_by_engine(self):
        sys.path.insert(0, str(ROOT.parent / "3_flag_hunter"))
        from cyf import catalog
        data = {"crypto": {"tools": [dict(name="RsaCtfTool", score=5, description="crypto", stars=10,
                    language="Python", pushed_at="2026-01-01", url="https://example.test/rsa")], "meta_lists": []}}
        with tempfile.TemporaryDirectory() as d:
            c.write_outputs(data, Path(d))
            with patch.object(catalog, "CATALOG_PATH", Path(d) / "tools_catalog.json"), patch.object(catalog, "_cache", None):
                self.assertEqual(catalog.catalog_weight("rsactftool", "crypto"), 1.0)
            self.assertEqual(json.loads((Path(d) / "tools_catalog.json").read_text()), data)


if __name__ == "__main__":
    unittest.main()
