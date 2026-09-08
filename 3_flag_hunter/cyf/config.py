"""
config.py — all the tunable numbers in one place. No generative model, no learning:
every weight here is hand-authored and printable, so you can justify any
decision the engine makes to a competition judge.
"""
import os

# The flag shape. Change CYF to your event's prefix (FLAG, CTF, picoCTF...).
FLAG_REGEX = r"(?:CYF|FLAG|CTF)\{[^}]{2,120}\}"

# Difficulty -> how much budget the engine spends before giving up.
# (steps = max tools it will run; timeout = per-tool seconds)
DIFFICULTY = {
    "easy":   {"max_steps": 4,  "timeout": 15},
    "medium": {"max_steps": 8,  "timeout": 30},
    "hard":   {"max_steps": 14, "timeout": 60},
}

# Base yield weight = "how often does this tool reveal something useful
# for this category." Hand-set from experience, 0..1. This is the
# deterministic stand-in for the ML action-ranker.
#   tool_name -> { category -> base_weight }
BASE_WEIGHTS = {
    "file_id":       {"*": 0.95},                       # always run first, cheap
    "strings_scan":  {"*": 0.55, "reverse": 0.7, "pwn": 0.6, "stego": 0.5},
    "decode_ladder": {"*": 0.60, "crypto": 0.85, "misc": 0.7},
    "binwalk_scan":  {"forensics": 0.8, "stego": 0.75, "hardware": 0.85, "*": 0.3},
    "exif_scan":     {"stego": 0.7, "osint": 0.8, "forensics": 0.5, "*": 0.15},
    "rsactftool":    {"crypto": 0.9, "*": 0.05},
    "zeratool_pwn":  {"pwn": 0.9, "*": 0.05},
    "stegseek":      {"stego": 0.9, "forensics": 0.4, "*": 0.05},
    "volatility":    {"forensics": 0.9, "*": 0.05},
    "web_sqlmap":    {"web": 0.85, "*": 0.05},
    "web_ffuf":      {"web": 0.6, "*": 0.05},
    "net_probe":     {"web": 0.5, "pwn": 0.6, "*": 0.05},
    "reverse_analyze": {"reverse": 0.85, "pwn": 0.3, "*": 0.05},
    "zsteg_scan":    {"stego": 0.85, "*": 0.05},
    "pcap_analyze":  {"forensics": 0.9, "*": 0.05},
    "jwt_attack":    {"web": 0.75, "*": 0.05},
    "nuclei_scan":   {"web": 0.55, "*": 0.05},
    "sherlock_search": {"osint": 0.7, "*": 0.05},
}

# --- external tool settings ---------------------------------------------
# Binary/command names (edit if yours are on a different path or name).
# The adapters look these up on PATH and skip cleanly if not found.
TOOL_BIN = {
    "rsactftool": ["RsaCtfTool", "rsactftool", "RsaCtfTool.py"],
    "zeratool":   ["zeratool", "zerapwn.py", "zeratool.py"],
    "stegseek":   ["stegseek"],
    "volatility": ["vol", "vol.py", "volatility3", "volatility"],
    "sqlmap":     ["sqlmap"],
    "ffuf":       ["ffuf"],
    "radare2":    ["radare2", "r2"],
    "zsteg":      ["zsteg"],
    "tshark":     ["tshark"],
    "jwt_tool":   ["jwt_tool.py", "jwt_tool"],
    "nuclei":     ["nuclei"],
    "sherlock":   ["sherlock"],
}

# How many TCP/UDP streams pcap_analyze will follow — capped so a huge
# capture can't turn one tool call into a multi-hour run.
PCAP_MAX_STREAMS = 40

# jwt_tool ships a small curated wordlist of real-world weak JWT secrets
# (jwt-common.txt) alongside its own repo — not on PATH by convention, so
# look in the couple of places a `git clone` or manual copy would leave it.
JWT_WORDLIST = next(
    (p for p in (os.path.expanduser("~/.local/share/jwt_tool/jwt-common.txt"),
                  os.path.expanduser("~/jwt_tool/jwt-common.txt"),
                  "/opt/jwt_tool/jwt-common.txt")
     if os.path.exists(p)),
    os.path.expanduser("~/.local/share/jwt_tool/jwt-common.txt"),
)

# Common claim/value pairs a CTF JWT challenge checks for the "become
# admin" condition — tried in order once the signing secret is cracked.
# Deterministic and printable, same spirit as every other weight here.
JWT_ADMIN_CLAIMS = [("role", "admin"), ("admin", "true"), ("isAdmin", "true"),
                     ("user", "admin"), ("username", "admin"), ("role", "administrator")]

# OSINT username target for sherlock — same pattern as CYF_URL/CYF_HOST:
#   CYF_USERNAME=someuser python run.py --category osint ...
OSINT_USERNAME = os.environ.get("CYF_USERNAME") or None

# sherlock's DEFAULT sweep checks 400+ sites and, measured here, simply
# doesn't fit any tool timeout this engine uses — many sites are slow or
# rate-limit datacenter IPs, and per-site --timeout doesn't bound the
# total wall-clock well when that many are borderline-slow rather than
# failing fast (a 60s run against ~6 scoped sites finished in ~3s; an
# unscoped run was killed at 60s with zero output). This curated list
# trades sherlock's real strength (breadth) for actually finishing within
# budget — a real, disclosed limitation, not a hidden one.
SHERLOCK_SITES = ["GitHub", "GitLab", "Reddit", "Docker Hub", "Keybase",
                   "PyPi", "Twitter", "Instagram", "YouTube", "Medium",
                   "Pastebin", "HackerNews", "Telegram"]

# Stegseek needs a wordlist; rockyou is the CTF default. The Kali package
# path (/usr/share/wordlists/rockyou.txt) is tried first for portability;
# falls back to a user-writable copy for boxes without root/apt access
# (this box: no sudo, so it lives under ~/wordlists/ instead).
STEGSEEK_WORDLIST = next(
    (p for p in ("/usr/share/wordlists/rockyou.txt",
                  os.path.expanduser("~/wordlists/rockyou.txt"))
     if os.path.exists(p)),
    "/usr/share/wordlists/rockyou.txt",  # keep as documented default even if absent
)

# Volatility plugins to try, in order (deterministic; stop at first useful).
# Was Windows-only before — a Linux/Mac memory image would silently get
# zero applicable plugins. banners.Banners is OS-agnostic (just sniffs the
# kernel banner string from the image) and runs first as a cheap sanity
# check; the rest are ordered fast-and-likely first. A plugin for the wrong
# OS just errors out cleanly (volatility3 says so on stderr) and the loop
# moves on — no OS pre-detection needed.
VOL_PLUGINS = ["banners.Banners",
               "linux.bash", "linux.pslist", "linux.pstree",
               "windows.info", "windows.pslist", "windows.cmdline",
               "windows.filescan"]

# Optional remote target for pwn (Zeratool can submit to a live server) and
# for the generic network prober (net_probe). Leave as None for local-only
# solving. Override without editing this file via env vars:
#   CYF_HOST=1.2.3.4 CYF_PORT=1337 python run.py ...
PWN_HOST = os.environ.get("CYF_HOST") or None
PWN_PORT = int(os.environ["CYF_PORT"]) if os.environ.get("CYF_PORT") else None

# Optional target URL for the web adapters (sqlmap/ffuf). Same idea:
#   CYF_URL=http://target:8080/ python run.py --category web ...
WEB_URL = os.environ.get("CYF_URL") or None

# Wordlist ffuf uses for path/dir fuzzing (small built-in list ships if this
# isn't present — see FFUF_FALLBACK_WORDS in tools.py).
FFUF_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
