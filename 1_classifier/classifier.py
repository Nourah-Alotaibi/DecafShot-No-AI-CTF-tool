#!/usr/bin/env python3
"""
CTF Category & Tool Classifier  —  Control Room pre-scan layer
==============================================================

A rule + traditional-ML cascade that takes a challenge and returns:
  category, confidence, recommended tools, and which policy tier resolved it.

Stages (each competition-legal on its own):
  1. RULE ENGINE   file-type + keyword signatures  -> SAFE tier
  2. ML CLASSIFIER TF-IDF + LogisticRegression on text -> SAFE tier
  (3. Manual review happens elsewhere, only if 1+2 are unsure -> REVIEW tier)

Usage:
    python classifier.py --train
    python classifier.py --path ./challenge_dir
    python classifier.py --text "We found an RSA public key, recover the flag"

Dependencies: scikit-learn, joblib  (pip install scikit-learn joblib)
"""

from __future__ import annotations
import argparse, json, os, re, subprocess, sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

MODEL_PATH = Path(__file__).with_name("ctf_clf.joblib")

# --------------------------------------------------------------------------
# Category -> recommended tools (mirrors the toolkit reference)
# --------------------------------------------------------------------------
TOOLS = {
    "web":       ["ffuf", "sqlmap", "nuclei", "Burp Suite", "jwt_tool"],
    "crypto":    ["RsaCtfTool", "CyberChef", "hashcat", "SageMath"],
    "reverse":   ["Ghidra", "radare2", "angr", "gdb-gef"],
    "pwn":       ["pwntools", "pwndbg", "ROPgadget", "one_gadget"],
    "forensics": ["Volatility3", "Wireshark", "binwalk", "foremost"],
    "stego":     ["zsteg", "steghide", "stegseek", "StegSolve"],
    "osint":     ["sherlock", "holehe", "exiftool", "Maltego"],
    "hardware":  ["binwalk", "FirmAE", "flashrom", "sigrok", "GNU Radio"],
}
CATEGORIES = list(TOOLS.keys())


@dataclass
class Result:
    category: str
    confidence: float
    tools: list = field(default_factory=list)
    tier: str = "SAFE"          # SAFE | REVIEW | BLOCKED
    resolved_by: str = "rule"   # rule | ml | needs_review
    signals: list = field(default_factory=list)

    def to_json(self):
        d = asdict(self)
        d["confidence"] = round(self.confidence, 3)
        return json.dumps(d, indent=2)


# ==========================================================================
# STAGE 1 — RULE ENGINE  (deterministic, explainable)
# ==========================================================================
# file-extension signatures
EXT_SIGNALS = {
    "pcap": "forensics", "pcapng": "forensics", "cap": "forensics",
    "raw": "forensics", "mem": "forensics", "vmem": "forensics", "dmp": "forensics",
    "png": "stego", "jpg": "stego", "jpeg": "stego", "bmp": "stego",
    "wav": "stego", "gif": "stego",
    "bin": "hardware", "img": "hardware", "hex": "hardware", "dfu": "hardware",
}

# keyword signatures: pattern -> (category, weight)
# Widened from the original hand-typed set after held-out phrasing checks
# (not in the training data) turned up real misses — e.g. "encrypt" was
# missing (only "decrypt" matched), "hide a message" didn't match "hidden".
# This is stage 1: deterministic and explainable, but still hand-authored,
# so treat any single miss as "add one more term," not a crisis — the ML
# stage and REVIEW tier exist specifically to catch what this doesn't.
KEYWORD_SIGNALS = [
    (r"\brsa\b|public key|modulus|\bn\s*=|\be\s*=|private key|de?crypt|cipher|\baes\b|xor|caesar|"
     r"base64|\bhash\b|prng|nonce|\becb\b|\bcbc\b|diffie|hellman|elliptic curve|\becc\b|hmac|"
     r"padding oracle|rot13|vigenere|vigen\xe8re|modular|prime factor|discrete log|md5|sha-?1|sha-?256", "crypto"),
    (r"http[s]?://|cookie|session|login|api|endpoint|\bsql\b|\bxss\b|\bjwt\b|admin panel|web ?app|"
     r"\burl\b|\bcsrf\b|\bssrf\b|template injection|\bssti\b|deserializ|graphql|oauth|\bcors\b|"
     r"websocket|http header|\bcrud\b|rest api", "web"),
    (r"buffer overflow|heap|\bfree\(|\bmalloc|shellcode|\brop\b|ret2|\bstack\b|segfault|\bpwn\b|libc|"
     r"canary|format string|use.after.free|double free|\baslr\b|got overwrite|one.gadget|seccomp|"
     r"integer overflow|\bnx\b\W|null pointer|arbitrary write|arbitrary read|vtable|hijack.{0,20}control.?flow", "pwn"),
    (r"reverse|decompile|disassemb|\bbinary\b|crackme|obfuscat|assembly|what does this program|"
     r"unpack|packer|bytecode|virtual machine|license check|\bserial\b|keygen|\bjni\b|\bapk\b|smali|"
     r"stripped binary", "reverse"),
    (r"memory dump|pcap|network traffic|volatility|carve|recover.*file|forensic|packet|registry|"
     r"event log|sqlite|write-ahead|deleted file|\busb\b capture|keystroke|email header|phishing|"
     r"wireshark|tcp stream|disk image|filesystem|windows event", "forensics"),
    (r"hidden|hide (a |the )?(message|data|secret|flag)|hiding (a |the )?(message|data|secret|flag)|"
     r"conceal|steg|least significant|spectrogram|inside (the )?image|embed|"
     r"whitespace|\bdct\b|\blsb\b|append(ed)? data|qr code|audio channel|hidden partition", "stego"),
    (r"username|social media|find (the )?person|open ?source intel|osint|geolocat|profile|"
     r"reverse image search|landmark|job posting|linkedin|phone number|deanonymiz|public records?|"
     r"vacation photo|hotel|shadow.*angle", "osint"),
    (r"firmware|uart|jtag|spi flash|\biot\b|embedded|solder|logic analyz|\bsdr\b|\brf\b|modbus|"
     r"voltage fault|\bglitch|bootloader|secure boot|desolder|can bus|\bplc\b|side channel|"
     r"power trace|flash chip", "hardware"),
]


def _run_file_cmd(p: Path) -> str:
    try:
        return subprocess.run(["file", "-b", str(p)], capture_output=True,
                              text=True, timeout=5).stdout.lower()
    except Exception:
        return ""


def rule_scan(text: str = "", path: str | None = None) -> Result | None:
    """Return a confident Result or None if rules are inconclusive."""
    scores = {c: 0.0 for c in CATEGORIES}
    signals = []
    blob = text.lower()

    # 1. inspect files on disk
    if path:
        pth = Path(path)
        files = [pth] if pth.is_file() else list(pth.rglob("*")) if pth.exists() else []
        for f in files:
            if not f.is_file():
                continue
            ext = f.suffix.lower().lstrip(".")
            if ext in EXT_SIGNALS:
                cat = EXT_SIGNALS[ext]
                scores[cat] += 2.0
                signals.append(f"ext:.{ext}->{cat}")
            fout = _run_file_cmd(f)
            if "elf" in fout or "pe32" in fout or "executable" in fout:
                # binary: pwn vs reverse — checksec-ish heuristic
                scores["pwn"] += 1.0
                scores["reverse"] += 1.0
                signals.append("file:executable->pwn/reverse")
            if "pcap" in fout or "capture file" in fout:
                scores["forensics"] += 2.0
                signals.append("file:pcap->forensics")
            blob += " " + fout

    # 2. keyword signatures on text (+ file output)
    for pattern, cat in KEYWORD_SIGNALS:
        hits = len(re.findall(pattern, blob))
        if hits:
            scores[cat] += hits * 1.0
            signals.append(f"kw:{cat}(+{hits})")

    total = sum(scores.values())
    if total == 0:
        return None
    best = max(scores, key=scores.get)
    conf = scores[best] / total
    # confident only if a clear winner
    ranked = sorted(scores.values(), reverse=True)
    margin = ranked[0] - (ranked[1] if len(ranked) > 1 else 0)
    if conf >= 0.5 and margin >= 1.0:
        return Result(category=best, confidence=conf, tools=TOOLS[best],
                      tier="SAFE", resolved_by="rule", signals=signals)
    return None  # hand to ML


# ==========================================================================
# STAGE 2 — ML CLASSIFIER  (TF-IDF + LogisticRegression, offline, traditional ML)
# ==========================================================================
def _starter_dataset():
    """Small labeled seed set. Replace/extend with scraped CTFtime + picoCTF data."""
    return [
        ("recover the flag from this RSA public key with small exponent", "crypto"),
        ("the message was encrypted with a repeating xor key, decrypt it", "crypto"),
        ("we intercepted an AES ciphertext and a padding oracle endpoint", "crypto"),
        ("classic caesar cipher, shift the letters to read the flag", "crypto"),
        ("crack this md5 hash to reveal the password", "crypto"),
        ("the login form seems vulnerable to sql injection, dump the users", "web"),
        ("find the hidden admin endpoint on this web application", "web"),
        ("this site sets a jwt cookie, forge one to become admin", "web"),
        ("reflected xss in the search box, steal the admin bot cookie", "web"),
        ("the api leaks other users data if you change the id parameter", "web"),
        ("exploit the buffer overflow to overwrite the return address", "pwn"),
        ("heap challenge, abuse the use after free to get a shell", "pwn"),
        ("build a rop chain to bypass NX and call system", "pwn"),
        ("format string vulnerability leaks the stack, leak libc", "pwn"),
        ("smash the stack, no canary, ret2win to the flag function", "pwn"),
        ("reverse this stripped binary to understand the check", "reverse"),
        ("decompile the crackme and find the correct serial", "reverse"),
        ("obfuscated assembly, figure out what input it wants", "reverse"),
        ("analyze this executable in ghidra to recover the algorithm", "reverse"),
        ("the program checks a password, disassemble to find it", "reverse"),
        ("analyze this memory dump with volatility to find the process", "forensics"),
        ("carve the deleted jpeg out of the disk image", "forensics"),
        ("inspect the pcap and follow the tcp stream for the flag", "forensics"),
        ("recover files from this corrupted filesystem image", "forensics"),
        ("the network capture hides credentials in http traffic", "forensics"),
        ("there is data hidden in the least significant bits of the png", "stego"),
        ("use steghide to extract the secret from this jpg", "stego"),
        ("the flag is embedded in the audio spectrogram", "stego"),
        ("something is concealed inside this innocent looking image", "stego"),
        ("zsteg this bitmap to reveal the hidden message", "stego"),
        ("find the target person from their username across social media", "osint"),
        ("geolocate where this photo was taken from its metadata", "osint"),
        ("open source intelligence: track down the account owner", "osint"),
        ("use exif data to find when and where the picture was shot", "osint"),
        ("search public records to identify the profile", "osint"),
        ("extract the router firmware and find hardcoded credentials", "hardware"),
        ("dump the spi flash chip over the uart interface", "hardware"),
        ("emulate this iot firmware image and attack the web panel", "hardware"),
        ("decode the captured sub-ghz rf signal with gnuradio", "hardware"),
        ("analyze the jtag debug interface on this embedded device", "hardware"),

        # second wave: different phrasing/register per category, so the
        # vectorizer isn't just memorizing the first batch's exact wording.
        ("given n and e, factor the modulus to get the private key", "crypto"),
        ("two rsa keys share a common factor, use that to break both", "crypto"),
        ("ecb mode leaks block patterns, exploit it to recover the flag", "crypto"),
        ("weak diffie-hellman parameters let you recover the shared secret", "crypto"),
        ("the flag was xored with a short repeating key and base64 encoded", "crypto"),
        ("bypass the auth check by tampering with the jwt algorithm field", "web"),
        ("server side template injection lets you read arbitrary files", "web"),
        ("this app is vulnerable to ssrf, hit the internal metadata endpoint", "web"),
        ("insecure deserialization in the cookie leads to rce", "web"),
        ("directory traversal in the file download parameter", "web"),
        ("null pointer write gives you a controlled write primitive", "pwn"),
        ("bypass aslr with an info leak then pop a shell", "pwn"),
        ("integer overflow in the size check leads to a heap overflow", "pwn"),
        ("write a fake vtable to hijack control flow in this cpp binary", "pwn"),
        ("seccomp filter blocks execve, find another syscall to escape", "pwn"),
        ("this apk is obfuscated with a custom packer, unpack and read the logic", "reverse"),
        ("the binary is statically linked, identify library functions first", "reverse"),
        ("virtual machine bytecode challenge, write an interpreter to trace it", "reverse"),
        ("license check uses a custom hash, reverse the algorithm", "reverse"),
        ("android app hides the flag behind a native jni call", "reverse"),
        ("windows event log shows a suspicious powershell command, find the flag", "forensics"),
        ("registry hive analysis reveals a persistence mechanism", "forensics"),
        ("recover the deleted sqlite rows from the write-ahead log", "forensics"),
        ("usb capture shows keystrokes being typed, decode them", "forensics"),
        ("email header analysis to trace the origin of this phishing message", "forensics"),
        ("appended data after the png IEND chunk hides a zip file", "stego"),
        ("whitespace at the end of each line encodes a binary message", "stego"),
        ("the wav file has a hidden signal in an unused audio channel", "stego"),
        ("qr code is corrupted, repair it to read the hidden text", "stego"),
        ("compare two nearly identical images to spot the hidden diff", "stego"),
        ("find the coordinates from a shadow's angle in the photo", "osint"),
        ("cross reference a username across forums to deanonymize the poster", "osint"),
        ("a company's public job postings leak their internal tech stack", "osint"),
        ("reverse image search to identify the landmark in the background", "osint"),
        ("scrape public records to link a phone number to a real name", "osint"),
        ("glitch the bootloader with a voltage fault to bypass secure boot", "hardware"),
        ("desolder the flash chip and read it with a spi programmer", "hardware"),
        ("can bus traffic from a car ecu needs to be decoded", "hardware"),
        ("modbus protocol on this plc leaks the setpoint value", "hardware"),
        ("side channel power trace reveals bits of the AES key", "hardware"),
    ]


SCRAPED_PATH = Path(__file__).with_name("scraped_dataset.json")


def _scraped_dataset():
    """Real labeled examples pulled from public CTF write-up repos by
    scrape_ctf_writeups.py — see that file for the method. Returns [] if
    it hasn't been run, so train() always works with just the hand-written
    seed set as a fallback."""
    if not SCRAPED_PATH.exists():
        return []
    try:
        rows = json.loads(SCRAPED_PATH.read_text())
        return [(r["text"], r["category"]) for r in rows if r.get("text") and r.get("category")]
    except Exception:
        return []


def train(save=True, use_scraped=True):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    import joblib

    hand_written = _starter_dataset()
    scraped = _scraped_dataset() if use_scraped else []
    # dedupe on exact text match (a handful of repos can share a challenge)
    seen, data = set(), []
    for text, cat in hand_written + scraped:
        if text not in seen:
            seen.add(text)
            data.append((text, cat))

    X, y = zip(*data)
    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
        ("clf", LogisticRegression(max_iter=1000, C=4.0)),
    ])
    pipe.fit(X, y)
    if save:
        joblib.dump(pipe, MODEL_PATH)
        print(f"[+] trained on {len(data)} examples "
              f"({len(hand_written)} hand-written + {len(scraped)} scraped, "
              f"deduped) -> {MODEL_PATH.name}")
    return pipe


def ml_scan(text: str, pipe=None) -> Result:
    import joblib
    if pipe is None:
        if not MODEL_PATH.exists():
            pipe = train()
        else:
            pipe = joblib.load(MODEL_PATH)
    proba = pipe.predict_proba([text])[0]
    classes = pipe.named_steps["clf"].classes_
    idx = proba.argmax()
    cat, conf = classes[idx], float(proba[idx])
    # top-2 for the signal trail
    order = proba.argsort()[::-1][:2]
    sig = [f"{classes[i]}:{proba[i]:.2f}" for i in order]
    return Result(category=cat, confidence=conf, tools=TOOLS[cat],
                  tier="SAFE", resolved_by="ml", signals=sig)


# ==========================================================================
# CASCADE — the Control Room dispatcher entrypoint
# ==========================================================================
def classify(text: str = "", path: str | None = None,
             ml_threshold: float = 0.55) -> Result:
    """Rule engine first; fall back to ML; flag for manual review only if ML is unsure."""
    r = rule_scan(text=text, path=path)
    if r is not None:
        return r
    # gather any file-command text so ML sees it too
    extra = ""
    if path and Path(path).exists():
        p = Path(path)
        files = [p] if p.is_file() else list(p.rglob("*"))
        extra = " ".join(_run_file_cmd(f) for f in files if f.is_file())
    m = ml_scan((text + " " + extra).strip() or "unknown challenge")
    if m.confidence < ml_threshold:
        m.tier = "REVIEW"
        m.resolved_by = "needs_review"
        m.signals.append(f"low_conf<{ml_threshold}: escalate to manual review")
    return m


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="CTF category & tool classifier")
    ap.add_argument("--train", action="store_true", help="train the ML model")
    ap.add_argument("--text", default="", help="challenge description text")
    ap.add_argument("--path", default=None, help="path to challenge file/dir")
    args = ap.parse_args()

    if args.train:
        train()
        return
    if not args.text and not args.path:
        ap.error("give --text and/or --path (or --train)")
    res = classify(text=args.text, path=args.path)
    print(res.to_json())


if __name__ == "__main__":
    main()
