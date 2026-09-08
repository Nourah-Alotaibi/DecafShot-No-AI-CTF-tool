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
}

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
