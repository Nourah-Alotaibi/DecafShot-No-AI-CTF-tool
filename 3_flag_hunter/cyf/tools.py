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


def _all_files(ev: Evidence):
    """Every file in scope: the original challenge files PLUS anything a
    tool has extracted so far (ev.extra_files) — see _ingest_extracted().
    Every Tool that gathers files to work on should use this, not
    _files_in(ev.challenge_path) directly, or it'll silently miss whatever
    got pulled out of a nested archive/capture/stego payload."""
    seen, out = set(), []
    for f in _files_in(ev.challenge_path) + ev.extra_files:
        rp = f.resolve()
        if rp not in seen:
            seen.add(rp)
            out.append(f)
    return out


def _classify_file(ev: Evidence, f: Path, timeout: int):
    """The signal-setting + text-ingestion logic every file needs, whether
    it came with the challenge (FileId) or was pulled out of one later
    (_ingest_extracted). Kept as one function so both paths stay in sync."""
    have_file = shutil.which("file")
    out = _sh(["file", "-b", str(f)], timeout).lower() if have_file else ""
    ev.add_fact(f"file: {f.name}: {out.strip()[:80]}" if out else f"file: {f.name}")
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
        # destroy that: any byte that isn't valid UTF-8 becomes a lossy
        # U+FFFD, and short binary-ish payloads are ALL such bytes.
        # latin-1 is a lossless 1-byte<->1-char mapping, so decode it that
        # way instead — small files only, cheap.
        try:
            if f.stat().st_size <= 65536:
                ev.add_text(f.read_bytes().decode("latin-1"))
        except Exception:
            pass


# Tools that operate on _all_files(ev) — i.e. can genuinely learn something
# new when a fresh file appears. Network-target tools (web_sqlmap, net_probe,
# jwt_attack, ...) aren't here: they key off config.WEB_URL/PWN_HOST, not
# files, so a new extracted file can't change what they'd do.
_FILE_CONSUMING_TOOLS = frozenset({
    "strings_scan", "binwalk_scan", "reverse_analyze", "exif_scan",
    "rsactftool", "zeratool_pwn", "stegseek", "zsteg_scan", "volatility",
})


def _ingest_extracted(ev: Evidence, path: Path, timeout: int = 10):
    """Call this whenever a tool PULLS a new file out of the challenge
    (binwalk extraction, a tshark HTTP object export, a zsteg -e payload,
    ...). Classifies it exactly like FileId would and adds it to
    ev.extra_files so every subsequent tool's _all_files(ev) sees it too —
    this is what lets a multi-stage challenge (stego -> zip -> ELF to
    reverse) actually chain instead of dead-ending after the first extract.

    Also un-marks every file-consuming tool as "already ran" (see
    _FILE_CONSUMING_TOOLS), so the ranker reconsiders them now that there's
    something genuinely new to look at — this closes what used to be a
    documented gap here: RsaCtfTool running early, finding no key file,
    then a LATER extraction revealing a .pem used to mean RsaCtfTool never
    got a second look at it. Deterministic, auditable, no learning: it's
    one rule ("new file -> old conclusions about files are stale"), not
    reasoning about WHICH tool might newly apply. The plain cost is a
    tool occasionally re-running and finding nothing new a second time
    (harmless, just spends a budget step) when the fresh file wasn't
    relevant to it anyway.
    """
    if not path.is_file():
        return
    rp = path.resolve()
    if any(f.resolve() == rp for f in ev.extra_files):
        return  # already ingested
    ev.extra_files.append(path)
    _classify_file(ev, path, timeout)
    ev.ran -= _FILE_CONSUMING_TOOLS


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
        for f in targets:
            _classify_file(ev, f, timeout)


class StringsScan(Tool):
    name = "strings_scan"
    def applicable(self, ev):
        if "strings_scan" in ev.ran: return 0.0
        return 1.0 if ev.has("binary", "executable", "image") or not ev.signals else 0.5
    def run(self, ev, timeout):
        have = shutil.which("strings")
        total = 0
        for f in _all_files(ev):
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
            # -e/-M actually pulls it out (recursively). Extracted files are
            # deliberately NOT cleaned up here (no rmtree) — _ingest_extracted
            # below stores Path references into ev.extra_files, not copies,
            # so every subsequent tool needs them to still exist on disk for
            # the rest of this run. Real multi-stage challenges are exactly
            # why this matters: an extracted file might itself be an ELF
            # that reverse_analyze should see, or a .pem that rsactftool
            # should try — not just more raw bytes for the flag regex.
            import tempfile
            tmpdir = tempfile.mkdtemp(prefix="cyf_binwalk_")
            for target in _files_in(ev.challenge_path):
                ex_out = _sh(["binwalk", "-e", "-M", "-C", tmpdir, str(target)], timeout)
                ev.add_text(ex_out)
            for extracted in Path(tmpdir).rglob("*"):
                if not extracted.is_file() or extracted.stat().st_size > 1_000_000:
                    continue
                extracted_count += 1
                _ingest_extracted(ev, extracted, timeout)

        ev.add_fact(f"binwalk: scanned for embedded data"
                    + (f", extracted {extracted_count} file(s) (now in scope for "
                       f"other tools)" if extracted_count else ""))


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
        bins = [f for f in _all_files(ev)
                if "elf" in _sh(["file", "-b", str(f)], 5).lower()] \
               if shutil.which("file") else _all_files(ev)
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
                      or "public" in f.name.lower() for f in _all_files(ev))
        rsa_sig = ("public key" in blob or re.search(r"\bn\s*=|\be\s*=|-----begin", blob))
        return 0.9 if (ev.category == "crypto" or keyfile or rsa_sig) else 0.05
    def run(self, ev, timeout):
        binname = _resolve("rsactftool")
        if not binname:
            ev.add_fact("RsaCtfTool not installed; skipping "
                        "(git clone RsaCtfTool/RsaCtfTool)"); return
        files = _all_files(ev)
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
        bins = [f for f in _all_files(ev)
                if "elf" in _sh(["file", "-b", str(f)], 5).lower()] \
               if shutil.which("file") else _all_files(ev)
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
        imgs = [f for f in _all_files(ev)
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


# --- REAL: zsteg (LSB / bit-plane stego, no passphrase needed) ------------
class ZstegScan(Tool):
    """Stegseek only cracks steghide-embedded data behind a wordlist-
    guessable passphrase. A large, common class of stego challenges has no
    passphrase at all — the payload is just hidden directly in the low
    bits of pixel channels (classic LSB) — which stegseek can't touch and
    nothing else in the registry covers. zsteg -a tries the standard set
    of bit-plane/channel/order combinations for PNG/BMP.
    """
    name = "zsteg_scan"
    def applicable(self, ev):
        if "zsteg_scan" in ev.ran: return 0.0
        return 0.85 if ev.has("image") else (0.3 if ev.category == "stego" else 0.05)
    def run(self, ev, timeout):
        binname = _resolve("zsteg")
        if not binname:
            ev.add_fact("zsteg not installed; skipping (gem install zsteg)"); return
        # zsteg is PNG/BMP-native; it can choke on other formats, so only
        # hand it those rather than every image in scope.
        imgs = [f for f in _all_files(ev) if f.suffix.lower() in (".png", ".bmp")]
        if not imgs:
            ev.add_fact("zsteg: no PNG/BMP carrier found"); return
        out = _sh([binname, "-a", str(imgs[0])], timeout)
        ev.add_text(out)
        f = find_flag(out)
        if f:
            ev.flag = f
            ev.add_fact(f"zsteg found the flag directly in {imgs[0].name} -> {f}")
            return
        # No direct hit — but zsteg's output lines often contain a payload
        # (base64, hex, raw text) that decode_ladder should get a crack at,
        # which ev.add_text(out) above already queued up for exactly that.
        ev.add_fact(f"zsteg: scanned {imgs[0].name} with -a (all methods), no direct flag")


# --- REAL: Volatility 3 (memory forensics) --------------------------------
class Volatility(Tool):
    name = "volatility"
    def applicable(self, ev):
        if "volatility" in ev.ran: return 0.0
        blob = " ".join(ev.facts).lower()
        mem = any(f.suffix.lower() in (".raw", ".mem", ".vmem", ".dmp", ".lime")
                  for f in _all_files(ev)) or "memory" in blob
        return 0.9 if (ev.category == "forensics" and mem) else (0.3 if mem else 0.05)
    def run(self, ev, timeout):
        binname = _resolve("volatility")
        if not binname:
            ev.add_fact("volatility not installed; skipping "
                        "(pip install volatility3)"); return
        imgs = [f for f in _all_files(ev)
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


# --- REAL: tshark (pcap stream reconstruction) -----------------------------
class PcapAnalyze(Tool):
    """FileId already sets the 'pcap' signal for a capture file — nothing
    consumed it until this. Reassembles every TCP/UDP stream to text (the
    actual content of the conversation, not just packet metadata) and
    exports any HTTP file transfers, feeding both into evidence: the
    reassembled streams go straight into the flag miner's text pool, and
    exported files get _ingest_extracted'd exactly like a binwalk find —
    so a pcap carrying, say, a file transfer that's itself a stego image
    or an encrypted blob chains into whatever tool handles that next.
    """
    name = "pcap_analyze"
    def applicable(self, ev):
        if "pcap_analyze" in ev.ran: return 0.0
        return 0.9 if ev.has("pcap") else 0.05
    def run(self, ev, timeout):
        binname = _resolve("tshark")
        if not binname:
            ev.add_fact("tshark not installed; skipping (apt install tshark)"); return
        caps = [f for f in _all_files(ev)
                if f.suffix.lower() in (".pcap", ".pcapng", ".cap")] or \
               [f for f in _all_files(ev) if ev.has("pcap")]
        if not caps:
            ev.add_fact("pcap_analyze: no capture file found"); return
        cap = caps[0]

        streams_seen = 0
        for proto in ("tcp", "udp"):
            idx_out = _sh([binname, "-r", str(cap), "-T", "fields",
                            "-e", f"{proto}.stream"], min(timeout, 15))
            indices = sorted({int(x) for x in idx_out.split() if x.isdigit()})
            for idx in indices[: config.PCAP_MAX_STREAMS]:
                stream_out = _sh([binname, "-r", str(cap), "-q", "-z",
                                   f"follow,{proto},ascii,{idx}"], min(timeout, 10))
                ev.add_text(stream_out)
                streams_seen += 1
                f = find_flag(stream_out)
                if f:
                    ev.flag = f
                    ev.add_fact(f"pcap_analyze: flag in {proto} stream {idx} of "
                                f"{cap.name} -> {f}")
                    return

        # HTTP file transfers: exported objects become first-class files —
        # this is the recursion point (see _ingest_extracted's docstring).
        extracted_count = 0
        import tempfile
        tmpdir = Path(tempfile.mkdtemp(prefix="cyf_pcap_"))
        _sh([binname, "-r", str(cap), "--export-objects", f"http,{tmpdir}"],
            min(timeout, 20))
        for obj in tmpdir.rglob("*"):
            if obj.is_file() and obj.stat().st_size <= 5_000_000:
                extracted_count += 1
                _ingest_extracted(ev, obj, timeout=10)

        ev.add_fact(f"pcap_analyze: followed {streams_seen} tcp/udp stream(s)"
                    + (f", exported {extracted_count} http object(s) (now in "
                       f"scope for other tools)" if extracted_count else "")
                    + f" from {cap.name}, no direct flag")


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
        # --flush-session: sqlmap caches results keyed by HOSTNAME ONLY (not
        # port or path) under ~/.local/share/sqlmap/output/<host>/ — found
        # by testing, not inspection: a second run against a different
        # port/challenge on the same host (very plausible in CTF contexts —
        # e.g. multiple challenges all on 127.0.0.1 or the same comp IP)
        # silently returned a STALE result from an unrelated earlier target
        # instead of querying the live one.
        cmd = [binname, "-u", config.WEB_URL, "--batch", "--level", "1",
               "--risk", "1", "--dump", "--answers", "quit=N", "--flush-session"]
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


# --- REAL: jwt_tool (crack weak HMAC secret, forge admin token) -----------
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


class JwtAttack(Tool):
    """Real crack-then-forge chain, not just a wrapper: (1) find a JWT in
    evidence text, (2) crack its HMAC secret against jwt_tool's own curated
    weak-secret wordlist, (3) if cracked, re-sign the token with each
    common 'become admin' claim override in turn and replay it against
    CYF_URL, checking the response for the flag. Verified end to end
    against a real Flask app with a weak HS256 secret — see
    tests/test_engine_smoke.py.
    """
    name = "jwt_attack"
    def applicable(self, ev):
        if "jwt_attack" in ev.ran: return 0.0
        has_jwt = any(_JWT_RE.search(b) for b in ev.text_blobs)
        return 0.85 if has_jwt else (0.2 if ev.category == "web" else 0.05)
    def run(self, ev, timeout):
        binname = _resolve("jwt_tool")
        if not binname:
            ev.add_fact("jwt_tool not installed; skipping "
                        "(git clone ticarpi/jwt_tool)"); return
        token = None
        for blob in ev.text_blobs:
            m = _JWT_RE.search(blob)
            if m:
                token = m.group(0); break
        if not token:
            ev.add_fact("jwt_attack: no JWT found in evidence text"); return

        if not os.path.exists(config.JWT_WORDLIST):
            ev.add_fact(f"jwt_attack: found a JWT but no wordlist at "
                        f"{config.JWT_WORDLIST} to crack it with"); return
        crack_out = _sh([binname, token, "-C", "-d", config.JWT_WORDLIST], timeout)
        ev.add_text(crack_out)
        m = re.search(r'([\'"]?)([^\s\'"]+)\1\s+is the CORRECT key', crack_out)
        if not m:
            ev.add_fact("jwt_attack: found a JWT, secret not in wordlist"); return
        secret = m.group(2)
        ev.add_fact(f"jwt_attack: cracked HMAC secret -> {secret!r}")

        for claim, value in config.JWT_ADMIN_CLAIMS:
            forge_out = _sh([binname, token, "-I", "-pc", claim, "-pv", value,
                              "-S", "hs256", "-p", secret], min(timeout, 10))
            m = re.search(r"(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\s*$",
                           forge_out.strip())
            if not m:
                continue
            forged = m.group(1)
            if config.WEB_URL:
                import urllib.request
                try:
                    req = urllib.request.Request(
                        config.WEB_URL, headers={"Authorization": f"Bearer {forged}"})
                    with urllib.request.urlopen(req, timeout=min(timeout, 10)) as r:
                        body = r.read(20000).decode(errors="replace")
                    ev.add_text(body)
                    f = find_flag(body)
                    if f:
                        ev.flag = f
                        ev.add_fact(f"jwt_attack: forged {claim}={value}, "
                                    f"replayed against {config.WEB_URL} -> {f}")
                        return
                except Exception:
                    pass
            else:
                ev.add_text(forged)
        ev.add_fact(f"jwt_attack: cracked secret {secret!r} and forged "
                    f"{len(config.JWT_ADMIN_CLAIMS)} admin-claim variants"
                    + (", no flag from replay" if config.WEB_URL else
                       " (set CYF_URL to replay them against a live endpoint)"))


# --- REAL: nuclei (known-CVE / misconfiguration scanning) ------------------
class NucleiScan(Tool):
    """Template-driven scanner for known vulnerabilities and common
    product/framework misconfigurations (default creds, debug endpoints,
    disclosed secrets, known CVEs, ...) — the class of web bug that isn't
    SQLi and isn't a fuzzable path, which nothing else in the registry
    covers. NOT the tool for "is there a bare .env/.git at the webroot" —
    that's ffuf's job (path fuzzing); nuclei's templates target specific
    known products/CVEs, not generic dotfile discovery. Needs
    `nuclei -update-templates` run once after install.

    Timing, measured honestly: even scoped to CTF-relevant tags, a real
    run against a live target took ~25-30s+ here — nuclei loads and tries
    many templates per tag. That's the entire "medium" difficulty budget
    (config.DIFFICULTY) gone on one tool; it realistically needs "hard"
    (60s) to reliably finish rather than get killed mid-scan by the
    subprocess timeout (which just means "no result", not a crash).
    """
    name = "nuclei_scan"
    def applicable(self, ev):
        if "nuclei_scan" in ev.ran: return 0.0
        return 0.8 if (ev.category == "web" and config.WEB_URL) else 0.05
    def run(self, ev, timeout):
        binname = _resolve("nuclei")
        if not binname:
            ev.add_fact("nuclei not installed; skipping "
                        "(see README for the release-binary install)"); return
        if not config.WEB_URL:
            ev.add_fact("nuclei_scan: no target set (export CYF_URL=http://host/)")
            return
        out = _sh([binname, "-u", config.WEB_URL, "-silent", "-nc",
                   "-tags", "exposures,misconfiguration,default-login,token-spray",
                   "-severity", "info,low,medium,high,critical",
                   "-timeout", "5"], timeout)
        ev.add_text(out)
        f = find_flag(out)
        if f:
            ev.flag = f
            ev.add_fact(f"nuclei found the flag directly -> {f}")
            return
        hits = [l for l in out.splitlines() if l.strip()]
        ev.add_fact(f"nuclei_scan: {len(hits)} finding(s) against {config.WEB_URL}"
                    + (f" (top: {hits[0][:100]})" if hits else ", none"))


# --- REAL: sherlock (username -> which sites they're registered on) -------
class SherlockSearch(Tool):
    """Real limitation, stated plainly: sherlock only tells you WHICH sites
    a username is registered on — it doesn't fetch profile content, so it
    can rarely produce the flag directly. What it's genuinely good for is
    recon evidence (site list as facts/text) that a human or a follow-up
    tool can act on, same role strings/file play for other categories.
    """
    name = "sherlock_search"
    def applicable(self, ev):
        if "sherlock_search" in ev.ran: return 0.0
        return 0.75 if (ev.category == "osint" and config.OSINT_USERNAME) else 0.05
    def run(self, ev, timeout):
        binname = _resolve("sherlock")
        if not binname:
            ev.add_fact("sherlock not installed; skipping "
                        "(pip install sherlock-project)"); return
        if not config.OSINT_USERNAME:
            ev.add_fact("sherlock_search: no username set "
                        "(export CYF_USERNAME=...)"); return
        cmd = [binname, config.OSINT_USERNAME, "--timeout", "6", "--print-found",
               "--no-color", "--no-txt"]
        for site in config.SHERLOCK_SITES:
            cmd += ["--site", site]
        out = _sh(cmd, timeout)
        ev.add_text(out)
        f = find_flag(out)
        if f:
            ev.flag = f
            ev.add_fact(f"sherlock found the flag directly -> {f}")
            return
        found = [l for l in out.splitlines() if l.strip().startswith("[+]")]
        ev.add_fact(f"sherlock_search: {config.OSINT_USERNAME} found on "
                    f"{len(found)} site(s)" + (f" — {found[0][:80]}" if found else ""))


REGISTRY = [FileId(), StringsScan(), DecodeLadder(), BinwalkScan(),
            ExifScan(), RsaCtfTool(), Zeratool(), Stegseek(), Volatility(),
            WebSqlmap(), WebFfuf(), NetProbe(), ReverseAnalyze(),
            ZstegScan(), PcapAnalyze(), JwtAttack(), NucleiScan(),
            SherlockSearch()]
