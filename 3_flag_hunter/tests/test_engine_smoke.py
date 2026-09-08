"""
test_engine_smoke.py — end-to-end regression tests for the real engine loop
(not just flag_miner in isolation). Each test skips cleanly if the real tool
it needs isn't installed on this machine, matching the engine's own
philosophy: everything is a real adapter, nothing is faked, so a test with
no tool installed is a skip, not a failure.

Run with:  python3 -m unittest discover -s tests
"""
import gzip
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyf.engine import hunt  # noqa: E402


def _write(dir_, name, data):
    p = Path(dir_) / name
    if isinstance(data, str):
        p.write_text(data)
    else:
        p.write_bytes(data)
    return p


class EngineSmokeTests(unittest.TestCase):
    def _hunt(self, category, files: dict, difficulty="medium"):
        with tempfile.TemporaryDirectory(prefix="cyf_test_") as d:
            for name, data in files.items():
                _write(d, name, data)
            ev, _ = hunt(category, difficulty, d, verbose=False)
            return ev

    def test_rot13_crypto(self):
        import codecs
        enc = codecs.encode("CYF{c4esar_sh1ft_by_13}", "rot13")
        ev = self._hunt("crypto", {"message.txt": enc})
        self.assertEqual(ev.flag, "CYF{c4esar_sh1ft_by_13}")

    def test_base64_gzip_crypto(self):
        import base64
        blob = base64.b64encode(gzip.compress(b"CYF{gz1p_1ns1de_b4se64}")).decode()
        ev = self._hunt("crypto", {"message.txt": blob})
        self.assertEqual(ev.flag, "CYF{gz1p_1ns1de_b4se64}")

    def test_repeating_xor_crib_crypto(self):
        key = b"k3y"
        raw = b"CYF{r3p3ating_x0r_kn0wn_pla1nt3xt}"
        ct = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
        ev = self._hunt("crypto", {"message.txt": ct})
        self.assertEqual(ev.flag, "CYF{r3p3ating_x0r_kn0wn_pla1nt3xt}")

    @unittest.skipUnless(shutil.which("binwalk"), "binwalk not installed")
    def test_binwalk_extracts_embedded_gzip(self):
        payload = gzip.compress(b"CYF{binw4lk_found_the_bur1ed_arch1ve}")
        data = b"\x00" * 512 + payload
        ev = self._hunt("forensics", {"dump.bin": data})
        self.assertEqual(ev.flag, "CYF{binw4lk_found_the_bur1ed_arch1ve}")

    @unittest.skipUnless(shutil.which("tshark"), "tshark not installed")
    def test_pcap_analyze_finds_flag_in_tcp_stream(self):
        # Regression for the dead-signal bug: FileId already set ev.has
        # ("pcap") for a capture file, but nothing consumed it until
        # PcapAnalyze existed. A base64-encoded flag in an HTTP header,
        # reassembled from raw TCP segments — this needs REAL stream
        # reassembly (tshark's follow,tcp), not just strings/grep on the
        # capture file (packet framing splits the payload across segments).
        try:
            from scapy.all import IP, TCP, Raw, wrpcap
        except ImportError:
            self.skipTest("scapy not installed")
        import base64
        flag_b64 = base64.b64encode(b"admin:CYF{tshark_stream_reassembly}").decode()
        c, s = ("10.0.0.1", 40000), ("10.0.0.2", 80)
        syn = IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="S", seq=1000)
        synack = IP(src=s[0], dst=c[0]) / TCP(sport=s[1], dport=c[1], flags="SA", seq=5000, ack=1001)
        ack = IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="A", seq=1001, ack=5001)
        payload = f"GET /login HTTP/1.1\r\nAuthorization: Basic {flag_b64}\r\n\r\n".encode()
        data_pkt = (IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="PA", seq=1001, ack=5001)
                    / Raw(load=payload))
        with tempfile.TemporaryDirectory(prefix="cyf_test_") as d:
            pcap_path = Path(d) / "test.pcap"
            wrpcap(str(pcap_path), [syn, synack, ack, data_pkt])
            ev, _ = hunt("forensics", "medium", str(pcap_path), verbose=False)
        self.assertEqual(ev.flag, "CYF{tshark_stream_reassembly}")

    @unittest.skipUnless(shutil.which("zsteg"), "zsteg not installed")
    def test_zsteg_finds_lsb_payload_stegseek_cant_touch(self):
        # stegseek only cracks steghide-embedded data behind a guessable
        # passphrase; raw LSB embedding (no passphrase at all) is a
        # different, common stego class it structurally can't reach.
        try:
            from PIL import Image
        except ImportError:
            self.skipTest("PIL not installed")
        import random
        flag = b"CYF{zsteg_lsb_test}\x00"
        bits = [(byte >> (7 - i)) & 1 for byte in flag for i in range(8)]
        rng = random.Random(3)
        w, h = 60, 60
        img = Image.new("RGB", (w, h))
        data = [(rng.randint(0, 255), rng.randint(0, 255), rng.randint(0, 255))
                for _ in range(w * h)]
        for i, bit in enumerate(bits):
            r, g, b = data[i]
            data[i] = ((r & ~1) | bit, g, b)
        img.putdata(data)
        with tempfile.TemporaryDirectory(prefix="cyf_test_") as d:
            png_path = Path(d) / "carrier.png"
            img.save(png_path)
            ev, _ = hunt("stego", "medium", str(png_path), verbose=False)
        self.assertEqual(ev.flag, "CYF{zsteg_lsb_test}")

    @unittest.skipUnless(shutil.which("tshark"), "tshark not installed")
    def test_recursive_extraction_pcap_to_gzip_object(self):
        # Regression for the structural fix: extracted/exported files used
        # to just get their raw bytes dumped into one undifferentiated text
        # blob — an extracted file that was itself a gzip archive (not
        # already-decompressed text) would never get decompressed. Now
        # _ingest_extracted classifies it like FileId would, so
        # decode_ladder's inflate step gets a real shot at it. Verified in
        # isolation (PcapAnalyze + DecodeLadder only, no binwalk in the
        # loop) so this attributes to the actual code path under test.
        try:
            from scapy.all import IP, TCP, Raw, wrpcap
        except ImportError:
            self.skipTest("scapy not installed")
        from cyf.evidence import Evidence
        from cyf.tools import PcapAnalyze, DecodeLadder

        body = gzip.compress(b"CYF{pcap_http_object_export_chained}")
        resp = (f"HTTP/1.1 200 OK\r\nContent-Type: application/gzip\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Content-Disposition: attachment; filename=secret.gz\r\n\r\n").encode() + body
        c, s = ("10.0.0.1", 40001), ("10.0.0.2", 80)
        syn = IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="S", seq=1000)
        synack = IP(src=s[0], dst=c[0]) / TCP(sport=s[1], dport=c[1], flags="SA", seq=5000, ack=1001)
        ack = IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="A", seq=1001, ack=5001)
        req = b"GET /secret.gz HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req_pkt = (IP(src=c[0], dst=s[0]) / TCP(sport=c[1], dport=s[1], flags="PA", seq=1001, ack=5001)
                   / Raw(load=req))
        ack2 = IP(src=s[0], dst=c[0]) / TCP(sport=s[1], dport=c[1], flags="A",
                                             seq=5001, ack=1001 + len(req))
        resp_pkt = (IP(src=s[0], dst=c[0]) / TCP(sport=s[1], dport=c[1], flags="PA",
                                                   seq=5001, ack=1001 + len(req))
                    / Raw(load=resp))
        with tempfile.TemporaryDirectory(prefix="cyf_test_") as d:
            pcap_path = Path(d) / "test.pcap"
            wrpcap(str(pcap_path), [syn, synack, ack, req_pkt, ack2, resp_pkt])
            ev = Evidence(category="forensics", challenge_path=str(pcap_path))
            PcapAnalyze().run(ev, 30)
            self.assertTrue(any(f.name == "secret.gz" for f in ev.extra_files),
                             "pcap_analyze should have exported and ingested secret.gz")
            DecodeLadder().run(ev, 10)
        self.assertEqual(ev.flag, "CYF{pcap_http_object_export_chained}")

    @unittest.skipUnless(shutil.which("exiftool"), "exiftool not installed")
    def test_exif_comment_osint(self):
        # Build the smallest possible JPEG-ish stand-in exiftool can tag —
        # rather than depend on PIL being installed, use exiftool itself to
        # both create and tag a minimal image via its own -o create option.
        with tempfile.TemporaryDirectory(prefix="cyf_test_") as d:
            img = Path(d) / "photo.jpg"
            import subprocess
            # 1x1 white JPEG, base64 of a minimal valid file
            import base64
            minimal_jpeg = base64.b64decode(
                "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkI"
                "CQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/2wBDAQMDAwQDBAgEBAgQCwkLEBAQEBAQ"
                "EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBD/wAARCAABAAEDASIA"
                "AhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAj/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFQEB"
                "AQAAAAAAAAAAAAAAAAAAAAX/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwCdABmX"
                "/9k="
            )
            img.write_bytes(minimal_jpeg)
            subprocess.run(["exiftool", "-Comment=CYF{ex1f_c0mment_l3aks_the_flag}",
                             "-overwrite_original", str(img)],
                            capture_output=True, timeout=10)
            ev, _ = hunt("osint", "medium", str(img), verbose=False)
            self.assertEqual(ev.flag, "CYF{ex1f_c0mment_l3aks_the_flag}")

    @unittest.skipUnless(shutil.which("zerapwn.py") and shutil.which("gcc"),
                          "zeratool or gcc not installed")
    def test_pwn_ret2win(self):
        # Requires patches/zeratool-fixes.patch applied — see README's
        # "pwn / Zeratool" section. Without it this will very likely fail
        # even though the binary is genuinely solvable (that's the whole
        # point of the patch). Compiles a fresh ret2win each run so this
        # doesn't depend on a binary checked into the repo matching the
        # local toolchain's ABI/addresses.
        import subprocess
        with tempfile.TemporaryDirectory(prefix="cyf_test_") as d:
            flag_file = Path(d) / "flag.txt"
            flag_file.write_text("CYF{r3t2win_pwn3d_by_zer4tool}\n")
            src = Path(d) / "ret2win.c"
            src.write_text(f'''
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
void win() {{ system("cat {flag_file}"); exit(0); }}
void vuln() {{ char buf[32]; read(0, buf, 200); }}
int main() {{
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("Give me input:");
    vuln();
    puts("Done");
    return 0;
}}
''')
            binpath = Path(d) / "ret2win"
            subprocess.run(["gcc", "-fno-stack-protector", "-fcf-protection=none",
                             "-no-pie", "-O0", "-o", str(binpath), str(src)],
                            capture_output=True, timeout=30, check=True)
            ev, _ = hunt("pwn", "hard", str(binpath), verbose=False)
            self.assertEqual(ev.flag, "CYF{r3t2win_pwn3d_by_zer4tool}")

    def test_rsa_weak_regression(self):
        # The original hand-crafted test fixture this project shipped with;
        # keep it under test so future changes can't silently break it.
        base = Path(__file__).resolve().parents[1] / "real_challenge"
        if not base.exists():
            self.skipTest("real_challenge fixture not present")
        ev, _ = hunt("crypto", "medium", str(base), verbose=False)
        self.assertEqual(ev.flag, "CYF{f3rmat_f4ct0r1zation_15_fun}")


if __name__ == "__main__":
    unittest.main()
