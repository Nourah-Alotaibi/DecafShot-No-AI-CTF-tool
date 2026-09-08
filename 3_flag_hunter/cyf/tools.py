"""
tools.py — the toolbox. Each Tool knows:
  - which categories it serves (base weights live in config)
  - applicable(evidence): a deterministic multiplier 0..1 from current evidence
  - run(evidence): shell out (or stub), write facts/signals/text back

Real adapters shell out to standard tools if installed and skip cleanly if
not. Heavy solvers (Zeratool, RsaCtfTool) are stubs you wire to the real
repos later — the ORCHESTRATION is the contribution, not re-implementing them.
"""
import os, shutil, subprocess, re
from pathlib import Path
from .evidence import Evidence
from .flag_miner import decode_ladder, find_flag
from . import config


def _sh(cmd, timeout):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        out = p.stdout + p.stderr
        # strip ANSI color codes so flag regex / parsing works on colored output
        return re.sub(r"\x1b\[[0-9;]*m", "", out)
    except Exception as e:
        return f"[tool error: {e}]"


def _resolve(key):
    """Return the first installed binary name for a tool key, or None."""
    for name in config.TOOL_BIN.get(key, []):
        if shutil.which(name):
            return name
    return None


def _files_in(challenge_path):
    p = Path(challenge_path)
    if p.is_file():
        return [p]
    return [f for f in p.rglob("*") if f.is_file()] if p.exists() else []


class Tool:
    name = "base"
    def applicable(self, ev: Evidence) -> float:  # 0 = skip, 1 = perfect fit
        return 1.0
    def run(self, ev: Evidence, timeout: int):
        raise NotImplementedError


# --- file magic: always first, seeds every other decision ---------------
class FileId(Tool):
    name = "file_id"
    def applicable(self, ev):
        return 1.0 if "file_id" not in ev.ran else 0.0
    def run(self, ev, timeout):
        targets = _files_in(ev.challenge_path)   # every file, whether path is file or dir
        if not targets:
            ev.add_fact("no files found at challenge path"); return
        have_file = shutil.which("file")
        for f in targets:
            out = _sh(["file", "-b", str(f)], timeout).lower() if have_file else ""
            ev.add_fact(f"file: {f.name}: {out.strip()[:80]}" if out
                        else f"file: {f.name}")
            if "elf" in out or "executable" in out or "pe32" in out:
                ev.add_signal("binary", "executable")
            if "pcap" in out or "capture file" in out:
                ev.add_signal("pcap")
            if "image" in out or "png" in out or "jpeg" in out:
                ev.add_signal("image")
            # load text content so the decode ladder can work immediately
            if (not have_file) or "ascii" in out or "text" in out or "json" in out:
                ev.add_signal("text")
                try:
                    ev.add_text(f.read_text(errors="replace"))
                except Exception:
                    pass
            elif "elf" not in out and "executable" not in out and "pe32" not in out:
                # `file` called it binary/"data" (not a known executable/image
                # format) — could just as easily be raw ciphertext, a short
                # ROT/XOR-scrambled blob, etc. UTF-8 + errors="replace" would
                # destroy that: any byte that isn't valid UTF-8 becomes a
                # lossy U+FFFD, and short binary-ish payloads are ALL such
                # bytes. latin-1 is a lossless 1-byte<->1-char mapping, so
                # decode it that way instead — small files only, cheap.
                try:
                    if f.stat().st_size <= 65536:
                        ev.add_text(f.read_bytes().decode("latin-1"))
                except Exception:
                    pass


class StringsScan(Tool):
    name = "strings_scan"
    def applicable(self, ev):
        if "strings_scan" in ev.ran: return 0.0
        return 1.0 if ev.has("binary", "executable", "image") or not ev.signals else 0.5
    def run(self, ev, timeout):
        have = shutil.which("strings")
        total = 0
        for f in _files_in(ev.challenge_path):
            if have:
                out = _sh(["strings", "-n", "6", str(f)], timeout)
            else:
                data = f.read_bytes()
                out = "".join(chr(b) if 32 <= b < 127 else "\n" for b in data)
            ev.add_text(out)
            total += len(out.splitlines())
            if re.search(r"[A-Za-z0-9+/]{16,}={0,2}", out):
                ev.add_signal("encoded_text")
        ev.add_fact(f"strings: {total} printable lines across files")


class DecodeLadder(Tool):
    name = "decode_ladder"
    def applicable(self, ev):
        if "decode_ladder" in ev.ran: return 0.0
        return 0.9 if ev.has("encoded_text", "text") else 0.4
    def run(self, ev, timeout):
        for blob in ev.text_blobs[-5:]:
            flag, trail = decode_ladder(blob)
            if flag:
                ev.flag = flag
                ev.add_fact(f"decode_ladder solved via {'->'.join(trail) or 'direct'}")
                return
        ev.add_fact("decode_ladder: no flag in current text")


class BinwalkScan(Tool):
    name = "binwalk_scan"
    def applicable(self, ev):
        if "binwalk_scan" in ev.ran: return 0.0
        return 0.9 if ev.has("binary", "image", "pcap") else 0.3
    def run(self, ev, timeout):
        if not shutil.which("binwalk"):
            ev.add_fact("binwalk not installed; skipping"); return
        # Pre-existing bug: `binwalk <directory>` silently produces NO
        # output at all (binwalk only scans files) — so this always missed
        # embedded data whenever challenge_path was a directory, which is
        # the common case (batch.py always passes one). Scan each file.
        out = "\n".join(_sh(["binwalk", str(target)], timeout)
                         for target in _files_in(ev.challenge_path))
        ev.add_text(out)
        found_embedded = bool(re.search(r"compressed|archive|zip|gzip|embedded", out, re.I))
        if found_embedded:
            ev.add_signal("embedded_files")

        extracted_count = 0
        if found_embedded:
            # A plain scan only REPORTS embedded data — it never reads it.
            # -e/-M actually pulls it out (recursively), which is the only
            # way something like "a gzip blob appended after a PNG" ever
            # gets its content into evidence for the flag miner to see.
            import tempfile
            tmpdir = tempfile.mkdtemp(prefix="cyf_binwalk_")
            try:
                for target in _files_in(ev.challenge_path):
                    ex_out = _sh(["binwalk", "-e", "-M", "-C", tmpdir, str(target)],
                                 timeout)
                    ev.add_text(ex_out)
                for extracted in Path(tmpdir).rglob("*"):
                    if not extracted.is_file() or extracted.stat().st_size > 1_000_000:
                        continue
                    extracted_count += 1
                    try:
                        ev.add_text(extracted.read_bytes().decode("latin-1"))
                    except Exception:
                        pass
            finally:
                shutil.rmtree(tmpdir, ignore_errors=True)

        ev.add_fact(f"binwalk: scanned for embedded data"
                    + (f", extracted {extracted_count} file(s)" if extracted_count else ""))


# --- REAL: static reverse-engineering pass (radare2 + objdump) ------------
class ReverseAnalyze(Tool):
    """Real static analysis for the 'reverse' category. Two parts:
      1. radare2 (aaa/afl/ii) for function/import facts a human would want.
      2. RAW bytes of .data/.rodata via objdump — deliberately not just
         GNU `strings`, which only extracts already-printable runs. An
         embedded flag that's been XOR'd/rotated in the binary is exactly
         NON-printable at rest, so strings alone will never surface it.
         Feeding the raw section bytes into evidence lets the flag miner's
         existing XOR/rotate sweep brute-force it — no new decode logic
         needed, just getting the real bytes where decode_ladder can see
         them.
    """
    name = "reverse_analyze"
    def applicable(self, ev):
        if "reverse_analyze" in ev.ran: return 0.0
        return 0.85 if ev.has("binary", "executable") else 0.1
    def run(self, ev, timeout):
        bins = [f for f in _files_in(ev.challenge_path)
                if "elf" in _sh(["file", "-b", str(f)], 5).lower()] \
               if shutil.which("file") else _files_in(ev.challenge_path)
        if not bins:
            ev.add_fact("reverse_analyze: no ELF binary found"); return
        target = bins[0]

        r2 = _resolve("radare2") or shutil.which("r2")
        if r2:
            out = _sh([r2, "-q", "-c", "aaa;afl;ii", str(target)], timeout)
            ev.add_text(out)
            n_funcs = len(re.findall(r"^\S+\s+\d+\s+\S+\s+\S+", out, re.M))
            ev.add_fact(f"reverse_analyze: r2 static analysis on {target.name} "
                        f"({n_funcs} function lines)")
        else:
            ev.add_fact("radare2 not installed; skipping static analysis "
                        "(apt install radare2)")

        objdump = shutil.which("objdump")
        sections_dumped = 0
        if objdump:
            for section in (".data", ".rodata"):
                out = _sh([objdump, "-s", "-j", section, str(target)], 10)
                # objdump prints "offset  hex hex hex hex  ascii" per line;
                # pull just the hex columns and turn them into real bytes —
                # latin-1 is lossless, so a non-printable/XOR'd byte survives
                # intact for the XOR sweep instead of being lost like it
                # would be trying to read the section as UTF-8 text.
                hexpairs = "".join(re.findall(r"^\s*[0-9a-f]+\s+((?:[0-9a-f]{2,8}\s+){1,4})",
                                               out, re.M))
                hexonly = re.sub(r"\s", "", hexpairs)
                if hexonly:
                    try:
                        raw = bytes.fromhex(hexonly)
                        ev.add_text(raw.decode("latin-1"))
                        sections_dumped += 1
                    except Exception:
                        pass
        ev.add_fact(f"reverse_analyze: dumped {sections_dumped} data section(s) "
                    f"raw (not just printable strings) from {target.name}"
                    if sections_dumped else
                    "reverse_analyze: objdump not available or no data sections")


class ExifScan(Tool):
    name = "exif_scan"
    def applicable(self, ev):
        if "exif_scan" in ev.ran: return 0.0
        return 0.9 if ev.has("image") else 0.1
    def run(self, ev, timeout):
        if not shutil.which("exiftool"):
            ev.add_fact("exiftool not installed; skipping"); return
        out = _sh(["exiftool", ev.challenge_path], timeout)
        ev.add_text(out)
        ev.add_fact("exif: read metadata")


# --- REAL: RsaCtfTool -----------------------------------------------------
class RsaCtfTool(Tool):
    name = "rsactftool"
    def applicable(self, ev):
        if "rsactftool" in ev.ran: return 0.0
        blob = " ".join(ev.text_blobs).lower()
        keyfile = any(f.suffix.lower() in (".pem", ".pub", ".key")
                      or "public" in f.name.lower() for f in _files_in(ev.challenge_path))
        rsa_sig = ("public key" in blob or re.search(r"\bn\s*=|\be\s*=|-----begin", blob))
        return 0.9 if (ev.category == "crypto" or keyfile or rsa_sig) else 0.05
    def run(self, ev, timeout):
        binname = _resolve("rsactftool")
        if not binname:
            ev.add_fact("RsaCtfTool not installed; skipping "
                        "(git clone RsaCtfTool/RsaCtfTool)"); return
        files = _files_in(ev.challenge_path)
        keys = [f for f in files if f.suffix.lower() in (".pem", ".pub", ".key")
                or "public" in f.name.lower()]
        if not keys:
            ev.add_fact("RsaCtfTool: no public key file found to attack"); return
        key = str(keys[0].resolve())

        # find a ciphertext file if one exists (cipher/enc/flag/ct .txt/.enc/.bin)
        ct = None
        for f in files:
            nm = f.name.lower()
            if f is keys[0]:
                continue
            if any(w in nm for w in ("cipher", "ct", "enc", "flag", "crypt", "secret")):
                ct = f
        if ct is None:  # fallback: any small non-key text file
            for f in files:
                if f is keys[0]: continue
                if f.suffix.lower() in (".txt", ".enc", ".bin") and f.stat().st_size < 4096:
                    ct = f; break
        raw = None
        if ct is not None:
            raw = ct.read_text(errors="replace").strip().split()[-1]

        # IMPORTANT: RsaCtfTool must be given ONE attack at a time — passing a
        # multi-attack list makes even a working attack report "cracking failed".
        # So we loop the fast offline attacks and stop at the first that solves.
        # Verified against this box's `RsaCtfTool --help` attack list — some
        # commonly-cited names (low_exponent, partial_key, common_modulus)
        # don't actually exist in the current tool; these do.
        attacks = ["fermat", "wiener", "boneh_durfee", "hastads",
                   "smallq", "small_crt_exp", "pollard_p_1",
                   "ecm", "roca", "partial_d", "common_modulus_related_message"]
        per = max(6, (timeout - 2) // len(attacks))   # split budget across attacks
        for atk in attacks:
            if raw is not None:
                cmd = [binname, "--publickey", key, "--decrypt", raw,
                       "--private", "--attack", atk]
            else:
                cmd = [binname, "--publickey", key, "--private", "--attack", atk]
            out = _sh(cmd, per + 4)
            ev.add_text(out)
            f = find_flag(out)
            if f:
                ev.flag = f
                ev.add_fact(f"RsaCtfTool cracked {keys[0].name} via {atk}"
                            + (" and decrypted the flag" if raw else ""))
                return
        ev.add_fact(f"RsaCtfTool ran {len(attacks)} attacks on {keys[0].name}"
                    + (f", decrypting {ct.name}" if ct else "")
                    + " (no flag; key may not be weak to these)")


# --- REAL: Zeratool (angr-based auto-exploit) -----------------------------
class Zeratool(Tool):
    name = "zeratool_pwn"
    def applicable(self, ev):
        if "zeratool_pwn" in ev.ran: return 0.0
        return 0.9 if (ev.category == "pwn" and ev.has("executable")) else 0.05
    def run(self, ev, timeout):
        binname = _resolve("zeratool")
        if not binname:
            ev.add_fact("Zeratool not installed; skipping (pip install zeratool)"); return
        bins = [f for f in _files_in(ev.challenge_path)
                if "elf" in _sh(["file", "-b", str(f)], 5).lower()] \
               if shutil.which("file") else _files_in(ev.challenge_path)
        if not bins:
            ev.add_fact("Zeratool: no binary to exploit"); return
        cmd = [binname, str(bins[0])]
        if config.PWN_HOST and config.PWN_PORT:
            cmd += ["-u", config.PWN_HOST, "-p", str(config.PWN_PORT)]
        out = _sh(cmd, timeout)
        ev.add_text(out)
        f = find_flag(out)
        if f: ev.flag = f
        ev.add_fact(f"Zeratool ran on {bins[0].name}"
                    + (f" -> {f}" if f else " (attempted auto-exploit)"))


# --- REAL: Stegseek (fast steghide cracker) -------------------------------
class Stegseek(Tool):
    name = "stegseek"
    def applicable(self, ev):
        if "stegseek" in ev.ran: return 0.0
        return 0.9 if ev.has("image") else (0.3 if ev.category == "stego" else 0.05)
    def run(self, ev, timeout):
        binname = _resolve("stegseek")
        if not binname:
            ev.add_fact("stegseek not installed; skipping "
                        "(apt install stegseek)"); return
        imgs = [f for f in _files_in(ev.challenge_path)
                if f.suffix.lower() in (".jpg", ".jpeg", ".png", ".bmp", ".wav")]
        if not imgs:
            ev.add_fact("stegseek: no image/audio carrier found"); return
        wl = config.STEGSEEK_WORDLIST
        # Use a real tempfile, not a path derived from challenge_path: that
        # used to be Path(ev.challenge_path).with_suffix(".stegout"), which
        # silently corrupts when challenge_path is a DIRECTORY — with_suffix
        # then drops the last path *component* and writes a stray sibling
        # file next to it (e.g. challenges/stego/foo/ -> challenges/stego/
        # foo.stegout), which then gets picked up as a bogus extra
        # "challenge" by batch.py on the next run.
        import tempfile, shutil as _shutil
        # a fresh directory guarantees the target FILE doesn't exist yet —
        # stegseek refuses to overwrite an existing file and, with no TTY
        # to answer its "overwrite? (y/n)" prompt, just hangs (mkstemp's
        # pre-created empty file triggered exactly that the first time).
        tmpdir = Path(tempfile.mkdtemp(prefix="cyf_stegseek_"))
        outpath = tmpdir / "out"
        try:
            out = _sh([binname, "--crack", str(imgs[0]), wl, str(outpath)], timeout)
            ev.add_text(out)
            # stegseek writes the extracted payload; read it if it appeared
            if outpath.exists() and outpath.stat().st_size > 0:
                try:
                    payload = outpath.read_text(errors="replace")
                    ev.add_text(payload)
                    f = find_flag(payload)
                    if f: ev.flag = f
                except Exception:
                    pass
        finally:
            _shutil.rmtree(tmpdir, ignore_errors=True)
        ev.add_fact(f"stegseek cracked {imgs[0].name}"
                    if "found passphrase" in out.lower()
                    else f"stegseek: no passphrase from {wl}")


# --- REAL: Volatility 3 (memory forensics) --------------------------------
class Volatility(Tool):
    name = "volatility"
    def applicable(self, ev):
        if "volatility" in ev.ran: return 0.0
        blob = " ".join(ev.facts).lower()
        mem = any(f.suffix.lower() in (".raw", ".mem", ".vmem", ".dmp", ".lime")
                  for f in _files_in(ev.challenge_path)) or "memory" in blob
        return 0.9 if (ev.category == "forensics" and mem) else (0.3 if mem else 0.05)
    def run(self, ev, timeout):
        binname = _resolve("volatility")
        if not binname:
            ev.add_fact("volatility not installed; skipping "
                        "(pip install volatility3)"); return
        imgs = [f for f in _files_in(ev.challenge_path)
                if f.suffix.lower() in (".raw", ".mem", ".vmem", ".dmp", ".lime")]
        if not imgs:
            ev.add_fact("volatility: no memory image found"); return
        for plugin in config.VOL_PLUGINS:
            out = _sh([binname, "-f", str(imgs[0]), plugin], timeout)
            ev.add_text(out)
            f = find_flag(out)
            if f:
                ev.flag = f
                ev.add_fact(f"volatility {plugin} -> {f}"); return
        ev.add_fact(f"volatility ran {len(config.VOL_PLUGINS)} plugins on "
                    f"{imgs[0].name} (no direct flag)")


# --- REAL: sqlmap (SQLi discovery + exploitation) -------------------------
class WebSqlmap(Tool):
    name = "web_sqlmap"
    def applicable(self, ev):
        if "web_sqlmap" in ev.ran: return 0.0
        return 0.9 if (ev.category == "web" and config.WEB_URL) else 0.05
    def run(self, ev, timeout):
        binname = _resolve("sqlmap")
        if not binname:
            ev.add_fact("sqlmap not installed; skipping (pip install sqlmap)"); return
        if not config.WEB_URL:
            ev.add_fact("web_sqlmap: no target set (export CYF_URL=http://host/path?id=1)")
            return
        cmd = [binname, "-u", config.WEB_URL, "--batch", "--level", "1",
               "--risk", "1", "--dump", "--answers", "quit=N"]
        out = _sh(cmd, timeout)
        ev.add_text(out)
        f = find_flag(out)
        if f: ev.flag = f
        ev.add_fact(f"sqlmap ran against {config.WEB_URL}"
                    + (f" -> {f}" if f else " (batch mode, level 1/risk 1; no flag)"))


# --- REAL: ffuf (fast content/path fuzzer) ---------------------------------
FFUF_FALLBACK_WORDS = ["admin", "flag", "flag.txt", "robots.txt", "backup",
                        ".git", ".env", "api", "login", "config", "secret",
                        "uploads", "console", "debug", "test"]

class WebFfuf(Tool):
    name = "web_ffuf"
    def applicable(self, ev):
        if "web_ffuf" in ev.ran: return 0.0
        return 0.7 if (ev.category == "web" and config.WEB_URL) else 0.05
    def run(self, ev, timeout):
        binname = _resolve("ffuf")
        if not binname:
            ev.add_fact("ffuf not installed; skipping (go install "
                        "github.com/ffuf/ffuf/v2@latest)"); return
        if not config.WEB_URL:
            ev.add_fact("web_ffuf: no target set (export CYF_URL=http://host/)")
            return
        base = config.WEB_URL.rstrip("/")
        wl = Path(config.FFUF_WORDLIST)
        if wl.exists():
            cmd = [binname, "-w", str(wl), "-u", f"{base}/FUZZ", "-mc",
                   "200,204,301,302,307,401,403", "-timeout", "5"]
        else:
            # no wordlist on disk: fuzz a small built-in list directly, one
            # request at a time, so the adapter still does something useful.
            hits = []
            for word in FFUF_FALLBACK_WORDS:
                out = _sh(["curl", "-s", "-o", "-", "-w", "\\n%{http_code}",
                            "--max-time", "5", f"{base}/{word}"], 8)
                ev.add_text(out)
                code = out.strip().splitlines()[-1] if out.strip() else ""
                if code in ("200", "204", "301", "302", "307", "401", "403"):
                    hits.append(f"{word} -> {code}")
                f = find_flag(out)
                if f:
                    ev.flag = f
                    ev.add_fact(f"web_ffuf(fallback) hit /{word} -> flag"); return
            ev.add_fact(f"web_ffuf: no wordlist at {wl}; probed "
                        f"{len(FFUF_FALLBACK_WORDS)} common paths directly, "
                        f"hits: {hits or 'none'}")
            return
        out = _sh(cmd, timeout)
        ev.add_text(out)
        f = find_flag(out)
        if f: ev.flag = f
        ev.add_fact(f"ffuf fuzzed {base}/FUZZ with {wl.name}"
                    + (f" -> {f}" if f else ""))


# --- REAL: generic network prober (stdlib only, no install needed) --------
class NetProbe(Tool):
    """Connects to config.PWN_HOST:PWN_PORT, reads whatever the service
    offers, and sweeps it for a flag. Covers the very common 'nc host port'
    style pwn/web challenge that nothing else in the registry touches."""
    name = "net_probe"
    def applicable(self, ev):
        if "net_probe" in ev.ran: return 0.0
        have_target = bool(config.PWN_HOST and config.PWN_PORT)
        return 0.8 if (have_target and ev.category in ("pwn", "web", "misc")) \
            else (0.3 if have_target else 0.0)
    def run(self, ev, timeout):
        import socket
        host, port = config.PWN_HOST, config.PWN_PORT
        if not (host and port):
            ev.add_fact("net_probe: no remote target set "
                        "(export CYF_HOST=... CYF_PORT=...)"); return
        chunks = []
        try:
            with socket.create_connection((host, port), timeout=min(timeout, 10)) as s:
                s.settimeout(min(timeout, 10))
                try:
                    chunks.append(s.recv(4096).decode("latin-1", "replace"))
                except socket.timeout:
                    pass
                # nudge it once in case it's waiting on input (menu prompt etc.)
                try:
                    s.sendall(b"\n")
                    chunks.append(s.recv(4096).decode("latin-1", "replace"))
                except (socket.timeout, OSError):
                    pass
        except OSError as e:
            ev.add_fact(f"net_probe: couldn't connect to {host}:{port} ({e})")
            return
        text = "".join(chunks)
        ev.add_text(text)
        f = find_flag(text)
        if f:
            ev.flag = f
            ev.add_fact(f"net_probe read banner from {host}:{port} -> flag"); return
        ev.add_fact(f"net_probe: connected to {host}:{port}, read "
                    f"{len(text)} bytes, no flag in banner")


REGISTRY = [FileId(), StringsScan(), DecodeLadder(), BinwalkScan(),
            ExifScan(), RsaCtfTool(), Zeratool(), Stegseek(), Volatility(),
            WebSqlmap(), WebFfuf(), NetProbe(), ReverseAnalyze()]
