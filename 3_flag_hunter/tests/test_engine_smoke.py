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
