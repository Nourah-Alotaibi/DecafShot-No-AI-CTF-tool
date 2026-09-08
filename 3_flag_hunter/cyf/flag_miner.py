"""
flag_miner.py — deterministic flag finder. Two parts:
  1. regex scan for the flag shape
  2. a bounded decode ladder (base64/base32/hex/rot13/rot47/atbash/url-decode/
     morse/gzip+zlib/single-byte-XOR/flag-crib multi-byte-XOR), recursing a
     few levels, checking the regex at every layer.
No generative model — this is the "magic" recipe done with plain rules.
"""
import base64, binascii, re, codecs, gzip, zlib, urllib.parse
from .config import FLAG_REGEX

_FLAG = re.compile(FLAG_REGEX)


def find_flag(text: str) -> str | None:
    m = _FLAG.search(text or "")
    return m.group(0) if m else None


# --- individual reversible decoders ------------------------------------
def _b64(s):
    try: return base64.b64decode(s + "=" * (-len(s) % 4)).decode("latin-1")
    except Exception: return None

def _b32(s):
    try: return base64.b32decode(s + "=" * (-len(s) % 8)).decode("latin-1")
    except Exception: return None

def _hex(s):
    try: return binascii.unhexlify(re.sub(r"\s", "", s)).decode("latin-1")
    except Exception: return None

def _rot13(s):
    try: return codecs.encode(s, "rot13")
    except Exception: return None

def _rot47(s):
    try:
        return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
                        for c in s)
    except Exception: return None

def _atbash(s):
    """A<->Z, B<->Y, ... classic substitution, letters only."""
    try:
        out = []
        for c in s:
            if "a" <= c <= "z":
                out.append(chr(ord("z") - (ord(c) - ord("a"))))
            elif "A" <= c <= "Z":
                out.append(chr(ord("Z") - (ord(c) - ord("A"))))
            else:
                out.append(c)
        return "".join(out)
    except Exception: return None

def _urldecode(s):
    try:
        out = urllib.parse.unquote(s)
        return out if out != s else None   # only useful if it actually changed something
    except Exception: return None

_MORSE = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f",
    "--.": "g", "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l",
    "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r",
    "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
    "-.--": "y", "--..": "z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}

def _morse(s):
    if not re.fullmatch(r"[.\-/ \n]+", s.strip() or "\0"):
        return None
    words = re.split(r"\s*/\s*|\n", s.strip())
    out_words = []
    for w in words:
        letters = [_MORSE.get(tok) for tok in w.split()]
        if not letters or None in letters:
            return None
        out_words.append("".join(letters))
    return " ".join(out_words) if out_words else None

def _inflate(s):
    """gzip/zlib magic bytes hiding in what looked like text/latin-1 bytes."""
    try:
        raw = s.encode("latin-1", "ignore")
        if raw[:2] == b"\x1f\x8b":
            return gzip.decompress(raw).decode("latin-1")
        if raw[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda"):
            return zlib.decompress(raw).decode("latin-1")
    except Exception:
        pass
    return None

def _plausible_flag_body(f, min_len=12, min_alnum_ratio=0.85):
    """Shared guard for the brute-force paths (xor1, xor_crib): a REAL flag
    body is long and overwhelmingly alnum/underscore
    ("f3rmat_f4ct0r1zation_15_fun", "test_flag_value"). A forged match from
    255-key or crib-derived brute force tends to be short and/or
    punctuation-heavy — this is what actually separates them in practice
    (found by adversarial fuzzing during development, not by inspection).
    Decoders that are deterministic bijective transforms (base64, rot13,
    ...) don't need this: their output IS the real content, not a guess."""
    body = f[f.index("{") + 1:-1]
    if len(body) < min_len:
        return False
    alnum_ratio = sum(c.isalnum() or c == "_" for c in body) / len(body)
    return alnum_ratio >= min_alnum_ratio


def _xor_bytes(s):
    """Yield all 255 single-byte XOR decodings (as strings)."""
    raw = s.encode("latin-1", "ignore")
    for k in range(1, 256):
        yield "".join(chr(b ^ k) for b in raw)

def _xor_crib(s, cribs=(b"CYF{", b"FLAG{", b"CTF{")):
    """Known-plaintext attack: if a repeating-key XOR ciphertext starts with
    one of the flag prefixes, XOR-ing the ciphertext's start against that
    crib recovers the key (or a multiple of it), which then decrypts the
    rest. Cheap and catches the classic 'flag prefix known' misc/crypto
    challenge without brute-forcing every key length.

    Guard: only a key whose FULL length equals the crib forces the crib's
    exact bytes at the start; every shorter/degenerate keylen tried here is
    just noise that can *coincidentally* satisfy the loose flag regex (a
    stray '}' within 120 bytes of garbage). So we additionally require the
    whole decoded message to be near-fully printable — a real repeating-key
    decode is ~100% printable end to end; forged noise measurably isn't.
    """
    raw = s.encode("latin-1", "ignore")
    for crib in cribs:
        if len(raw) <= len(crib):
            continue
        key = bytes(a ^ b for a, b in zip(raw, crib))
        for keylen in range(1, len(crib) + 1):
            k = key[:keylen]
            if len(set(k)) == 1 and keylen > 1:
                continue  # degenerate (same as single-byte XOR, already covered)
            out = bytes(b ^ k[i % keylen] for i, b in enumerate(raw))
            text = out.decode("latin-1")
            printable = sum(1 for c in text if 32 <= ord(c) <= 126 or c in "\n\t\r")
            if printable / len(text) < 0.99:
                continue          # reject: this keylen didn't really decode it
            f = find_flag(text)
            if f and _plausible_flag_body(f):
                return text
    return None

DECODERS = [("base64", _b64), ("base32", _b32), ("hex", _hex), ("rot13", _rot13),
            ("rot47", _rot47), ("atbash", _atbash), ("urldecode", _urldecode),
            ("morse", _morse), ("inflate", _inflate)]


def decode_ladder(text: str, depth: int = 3) -> tuple[str | None, list]:
    """
    Try to peel encodings off `text` until a flag appears.
    Returns (flag_or_None, trail_of_transforms_used).
    """
    # direct hit first
    f = find_flag(text)
    if f:
        return f, []

    frontier = [(text, [])]
    seen = set()
    for _ in range(depth):
        nxt = []
        for blob, trail in frontier:
            # candidate tokens: whole blob + long word-ish chunks.
            # split on non-payload chars so 'secret=Q1lG...' -> 'Q1lG...'
            raw_tokens = re.findall(r"[A-Za-z0-9+/]{8,}={0,2}", blob)
            tokens = [blob] + raw_tokens
            for tok in tokens[:12]:                 # cap breadth
                for name, fn in DECODERS:
                    out = fn(tok)
                    if not out or out in seen:
                        continue
                    seen.add(out)
                    f = find_flag(out)
                    if f:
                        return f, trail + [name]
                    magic = out.encode("latin-1", "ignore")[:2]
                    is_compressed = magic == b"\x1f\x8b" or magic in (b"\x78\x9c", b"\x78\x01", b"\x78\xda")
                    if out.isprintable() or "{" in out or is_compressed:
                        nxt.append((out, trail + [name]))
            # XOR sweeps run once per frontier blob (not per extracted
            # sub-token), and only when two things both hold:
            #  1. trail so far is empty, or is a pure byte-materializing
            #     decode (base64/32/hex) — chaining after a substitution
            #     cipher (rot47/atbash/...) isn't how real challenges are
            #     built, and empirically it's exactly the combination that
            #     manufactures false-positive "flags" out of noise.
            #  2. the blob doesn't itself look like a clean, still-encoded
            #     base64 string. XOR-ing base64 TEXT before decoding it is
            #     cryptographic nonsense and was the actual source of every
            #     false positive found in testing (a small printable
            #     alphabet XORed with a short key stays "printable-ish"
            #     far too often to trust). Real ciphertext should already
            #     be raw bytes-as-text by this point, or one base64/hex
            #     decode away from it — which the DECODERS loop above
            #     already queues into the next depth.
            looks_like_base64 = bool(re.fullmatch(r"[A-Za-z0-9+/=\s]{8,}", blob))
            if all(t in ("base64", "base32", "hex") for t in trail) and not looks_like_base64:
                # single-byte XOR is noisy: only check for a flag, don't recurse.
                # Same plausibility guard as xor_crib — 255 brute-forced keys
                # against real data is fine, but against noise the loose flag
                # regex can occasionally be satisfied by chance (found via
                # adversarial fuzzing during development).
                for out in _xor_bytes(blob):
                    f = find_flag(out)
                    if f and _plausible_flag_body(f):
                        return f, trail + ["xor1"]
                # known-plaintext (flag-prefix crib) repeating-key XOR
                crib_out = _xor_crib(blob)
                if crib_out:
                    f = find_flag(crib_out)
                    if f:
                        return f, trail + ["xor_crib"]
        frontier = nxt[:20]                          # cap frontier size
    return None, []
