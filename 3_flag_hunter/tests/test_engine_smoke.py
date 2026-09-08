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

    @unittest.skipUnless(shutil.which("jwt_tool.py") or shutil.which("jwt_tool"),
                          "jwt_tool not installed")
    def test_jwt_attack_cracks_weak_secret_and_forges_admin(self):
        # Real crack-then-forge chain against a live Flask app with a
        # weak HS256 secret ("secret" — on jwt_tool's own wordlist).
        try:
            import jwt as pyjwt
        except ImportError:
            self.skipTest("pyjwt not installed")
        import os as _os
        from cyf import config as cyf_config

        secret = "secret"
        flag = "CYF{jwt_test_weak_secret_forged}"
        token = pyjwt.encode({"user": "guest", "role": "user"}, secret, algorithm="HS256")

        from http.server import BaseHTTPRequestHandler, HTTPServer
        import threading, json as _json

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                auth = self.headers.get("Authorization", "")
                tok = auth.replace("Bearer ", "")
                try:
                    claims = pyjwt.decode(tok, secret, algorithms=["HS256"])
                except Exception:
                    self.send_response(401); self.end_headers(); return
                if claims.get("role") == "admin":
                    body = _json.dumps({"flag": flag}).encode()
                    self.send_response(200)
                else:
                    body = b'{"error":"not admin"}'
                    self.send_response(403)
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *a):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            old_url = cyf_config.WEB_URL
            cyf_config.WEB_URL = f"http://127.0.0.1:{port}/admin"
            from cyf.evidence import Evidence
            from cyf.tools import JwtAttack
            ev = Evidence(category="web", challenge_path=".")
            ev.add_text(f"Set-Cookie: session={token}; HttpOnly")
            JwtAttack().run(ev, 30)
        finally:
            cyf_config.WEB_URL = old_url
            server.shutdown()
            server.server_close()
        self.assertEqual(ev.flag, flag)

    @unittest.skipUnless(shutil.which("sherlock"), "sherlock not installed")
    def test_sherlock_finds_known_real_account(self):
        # Real network call to real sites — checks a well-known, stable
        # account (Linus Torvalds' GitHub) rather than asserting exact
        # site-by-site results, which would be fragile to those services
        # changing over time. Scoped site list per config.SHERLOCK_SITES
        # (measured: unscoped sherlock sweeps don't fit any timeout this
        # engine uses — see the comment on that config value).
        from cyf import config as cyf_config
        from cyf.evidence import Evidence
        from cyf.tools import SherlockSearch
        old = cyf_config.OSINT_USERNAME
        try:
            cyf_config.OSINT_USERNAME = "torvalds"
            ev = Evidence(category="osint", challenge_path=".")
            SherlockSearch().run(ev, 25)
        finally:
            cyf_config.OSINT_USERNAME = old
        self.assertTrue(any("found on" in f and "torvalds" in f for f in ev.facts))
        self.assertFalse(any("found on 0 site" in f for f in ev.facts),
                          f"expected at least one real hit: {ev.facts}")

    @unittest.skipUnless(shutil.which("sqlmap"), "sqlmap not installed")
    def test_web_sqlmap_dumps_flag_from_live_sqli(self):
        # Real vulnerable target: raw string interpolation into a SQL
        # query, the classic CTF-style SQLi. sqlite3 is stdlib so this
        # needs nothing beyond sqlmap itself.
        import sqlite3, threading
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from urllib.parse import urlparse, parse_qs

        flag = "CYF{sqlmap_test_dumped_flag}"
        with tempfile.TemporaryDirectory(prefix="cyf_test_") as d:
            db_path = str(Path(d) / "db.sqlite3")
            con = sqlite3.connect(db_path)
            con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, flag TEXT)")
            con.execute("INSERT INTO users (username, flag) VALUES ('admin', ?)", (flag,))
            con.commit(); con.close()

            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    qs = parse_qs(urlparse(self.path).query)
                    uid = qs.get("id", ["1"])[0]
                    con = sqlite3.connect(db_path)
                    cur = con.cursor()
                    try:
                        cur.execute(f"SELECT username, flag FROM users WHERE id = {uid}")
                        rows = cur.fetchall()
                        body = json.dumps({"rows": rows}).encode()
                        self.send_response(200)
                    except Exception as e:
                        body = str(e).encode()
                        self.send_response(500)
                    con.close()
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)
                def log_message(self, *a):
                    pass

            import json
            server = HTTPServer(("127.0.0.1", 0), Handler)
            port = server.server_address[1]
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                from cyf import config as cyf_config
                old_url = cyf_config.WEB_URL
                cyf_config.WEB_URL = f"http://127.0.0.1:{port}/user?id=1"
                from cyf.evidence import Evidence
                from cyf.tools import WebSqlmap
                ev = Evidence(category="web", challenge_path=".")
                WebSqlmap().run(ev, 60)
            finally:
                cyf_config.WEB_URL = old_url
                server.shutdown()
                server.server_close()
        self.assertEqual(ev.flag, flag)

    @unittest.skipUnless(shutil.which("ffuf"), "ffuf not installed")
    def test_web_ffuf_finds_exposed_file(self):
        # No wordlist needed on this box (config.FFUF_WORDLIST absent) —
        # exercises the curl-fallback probe path against a real static
        # file server, same as validated ad hoc earlier this session, now
        # a permanent regression test.
        import threading
        from http.server import HTTPServer, SimpleHTTPRequestHandler
        from functools import partial

        flag = "CYF{ffuf_test_found_flag}"
        with tempfile.TemporaryDirectory(prefix="cyf_test_") as d:
            (Path(d) / "flag.txt").write_text(flag)
            handler = partial(SimpleHTTPRequestHandler, directory=d)
            server = HTTPServer(("127.0.0.1", 0), handler)
            port = server.server_address[1]
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                from cyf import config as cyf_config
                old_url = cyf_config.WEB_URL
                cyf_config.WEB_URL = f"http://127.0.0.1:{port}"
                from cyf.evidence import Evidence
                from cyf.tools import WebFfuf
                ev = Evidence(category="web", challenge_path=".")
                WebFfuf().run(ev, 30)
            finally:
                cyf_config.WEB_URL = old_url
                server.shutdown()
                server.server_close()
        self.assertEqual(ev.flag, flag)

    def test_net_probe_reads_banner_from_live_socket(self):
        # stdlib-only tool, no external binary — always runs.
        import socket, threading

        flag = "CYF{net_probe_test_banner}"
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve():
            conn, _ = listener.accept()
            conn.sendall(f"welcome\nhere's your banner: {flag}\n".encode())
            conn.close()

        threading.Thread(target=serve, daemon=True).start()
        try:
            from cyf import config as cyf_config
            old_host, old_port = cyf_config.PWN_HOST, cyf_config.PWN_PORT
            cyf_config.PWN_HOST, cyf_config.PWN_PORT = "127.0.0.1", port
            from cyf.evidence import Evidence
            from cyf.tools import NetProbe
            ev = Evidence(category="pwn", challenge_path=".")
            NetProbe().run(ev, 10)
        finally:
            cyf_config.PWN_HOST, cyf_config.PWN_PORT = old_host, old_port
            listener.close()
        self.assertEqual(ev.flag, flag)

    @unittest.skipUnless(shutil.which("nuclei"), "nuclei not installed")
    def test_nuclei_scan_skips_cleanly_without_target(self):
        # A full positive test would need a live nuclei-detectable
        # misconfiguration AND enough time for a real scan — measured at
        # ~25-30s+ even scoped (see NucleiScan's own docstring), too slow
        # for a routine regression run. This locks in what IS fast and
        # real: correct graceful-skip behavior when no target is set,
        # so a broken config.WEB_URL check can't silently start scanning
        # something unintended.
        from cyf.evidence import Evidence
        from cyf.tools import NucleiScan
        ev = Evidence(category="web", challenge_path=".")
        NucleiScan().run(ev, 5)
        self.assertIsNone(ev.flag)
        self.assertTrue(any("no target set" in f for f in ev.facts), ev.facts)

    @unittest.skipUnless(shutil.which("binwalk") and shutil.which("RsaCtfTool"),
                          "binwalk or RsaCtfTool not installed")
    def test_tool_reconsiders_after_new_file_extracted(self):
        # The "smarter, still fully deterministic" fix: a tool that already
        # ran and found nothing used to never get reconsidered even when a
        # LATER extraction revealed exactly what it needed (documented as a
        # known limitation when _ingest_extracted was first built). Now
        # _ingest_extracted un-marks file-consuming tools as "ran" when a
        # new file appears, so the ranker notices and gives them another
        # shot — verified here for real: RsaCtfTool runs first (no key
        # file exists yet, at the top level), fails cleanly, THEN binwalk
        # extracts a zip containing pub.pem+cipher.txt, and RsaCtfTool
        # must get re-ranked and actually solve it on its second run.
        import zipfile, io
        real_challenge = Path(__file__).resolve().parents[1] / "real_challenge"
        if not real_challenge.exists():
            self.skipTest("real_challenge fixture not present")
        with tempfile.TemporaryDirectory(prefix="cyf_test_") as d:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                z.writestr("pub.pem", (real_challenge / "pub.pem").read_text())
                z.writestr("cipher.txt", (real_challenge / "cipher.txt").read_text())
            carrier = Path(d) / "carrier.bin"
            carrier.write_bytes(b"\x00" * 512 + buf.getvalue())
            ev, log = hunt("crypto", "medium", str(d), verbose=False)
        self.assertEqual(ev.flag, "CYF{f3rmat_f4ct0r1zation_15_fun}")
        # confirm it's genuinely a *second* run, not a lucky first pass —
        # rsactftool must appear as having failed once before succeeding
        rsactftool_facts = [f for f in ev.facts if "rsactftool" in f.lower()
                             or "RsaCtfTool" in f]
        self.assertTrue(
            any("no public key" in f for f in rsactftool_facts),
            f"expected an initial failed attempt in the log: {ev.facts}")


if __name__ == "__main__":
    unittest.main()
