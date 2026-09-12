"""Portable regression checks; mocks test contracts, not real solver success."""
import base64
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyf import config
from cyf.engine import hunt
from cyf.evidence import Evidence
from cyf.help import CAPABILITIES, describe_tools
from cyf.tools import REGISTRY, DecodeLadder, ExifScan, BinwalkScan, RsaCtfTool, _ingest_extracted

ROOT = Path(__file__).resolve().parents[2]


class PortableTests(unittest.TestCase):
    def test_every_category_can_decode_without_external_tools(self):
        with tempfile.TemporaryDirectory() as d, patch("cyf.tools.shutil.which", return_value=None):
            p = Path(d) / "message.txt"
            p.write_bytes(base64.b64encode(b"FLAG{portable_category_check}"))
            for category in ("web", "crypto", "reverse", "pwn", "forensics", "stego", "osint", "hardware", "misc"):
                with self.subTest(category=category):
                    with patch.multiple(config, WEB_URL=None, PWN_HOST=None, PWN_PORT=None, OSINT_USERNAME=None):
                        ev, _ = hunt(category, "medium", str(p), verbose=False)
                    self.assertEqual(ev.flag, "FLAG{portable_category_check}")

    def test_every_adapter_handles_no_dependencies_or_targets(self):
        with tempfile.TemporaryDirectory() as d, patch("cyf.tools.shutil.which", return_value=None):
            for tool in REGISTRY:
                with self.subTest(adapter=tool.name):
                    ev = Evidence(category="misc", challenge_path=d)
                    with patch.multiple(config, WEB_URL=None, PWN_HOST=None, PWN_PORT=None, OSINT_USERNAME=None):
                        tool.run(ev, 1)
                    self.assertIsNone(ev.flag)
                    self.assertTrue(ev.facts)

    def test_new_file_reopens_decoder_and_capture_analysis(self):
        with tempfile.TemporaryDirectory() as d, patch("cyf.tools.shutil.which", return_value=None):
            p = Path(d) / "new.txt"
            p.write_bytes(base64.b64encode(b"FLAG{new_evidence_reconsidered}"))
            ev = Evidence(category="misc", challenge_path=d)
            ev.ran.update({"decode_ladder", "pcap_analyze"})
            _ingest_extracted(ev, p)
            self.assertNotIn("decode_ladder", ev.ran)
            self.assertNotIn("pcap_analyze", ev.ran)
            DecodeLadder().run(ev, 1)
            self.assertEqual(ev.flag, "FLAG{new_evidence_reconsidered}")

    def test_metadata_and_binwalk_consume_extracted_files(self):
        with tempfile.TemporaryDirectory() as original, tempfile.TemporaryDirectory() as extracted:
            p = Path(extracted) / "new.bin"
            p.write_bytes(b"metadata")
            for tool in (ExifScan(), BinwalkScan()):
                ev = Evidence(category="forensics", challenge_path=original)
                ev.extra_files.append(p)
                with patch("cyf.tools.shutil.which", return_value="installed"), patch("cyf.tools._sh", return_value="plain data") as shell:
                    tool.run(ev, 1)
                self.assertTrue(any(str(p) in call.args[0] for call in shell.call_args_list))

    def test_empty_ciphertext_does_not_crash(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "pub.pem").write_text("test key")
            (Path(d) / "cipher.txt").write_text("")
            ev = Evidence(category="crypto", challenge_path=d)
            with patch("cyf.tools._resolve", return_value="RsaCtfTool"), patch("cyf.tools._sh", return_value="no result") as shell:
                RsaCtfTool().run(ev, 1)
            self.assertTrue(shell.called)
            self.assertTrue(all("--decrypt" not in call.args[0] for call in shell.call_args_list))

    def test_inventory_is_complete_and_never_executes_tools(self):
        self.assertEqual(set(CAPABILITIES), {t.name for t in REGISTRY})
        with patch("subprocess.run", side_effect=AssertionError("doctor executed a tool")):
            report = describe_tools(check=True)
        for tool in REGISTRY:
            self.assertIn(tool.name, report)

    def test_cli_information_and_validation(self):
        for option in ("--help", "--guide", "--list-tools", "--doctor"):
            result = subprocess.run([sys.executable, str(ROOT / "3_flag_hunter/run.py"), option], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.stdout)
        for args in ([], ["--path", "nonexistent-challenge"], ["--category", "typo", "--path", "."]):
            result = subprocess.run([sys.executable, str(ROOT / "3_flag_hunter/run.py"), *args], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
