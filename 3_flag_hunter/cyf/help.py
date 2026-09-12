"""Offline capability inventory. Discovery never executes an external tool."""
import shutil
from pathlib import Path
from . import config
from .tools import REGISTRY

# adapter -> description, dependency groups (one executable per group suffices)
CAPABILITIES = {
    "file_id": ("Identify files; basic fallback without file", [("file",)]),
    "strings_scan": ("Extract printable text; Python fallback available", [("strings",)]),
    "decode_ladder": ("Decode base64/32, hex, rotations, gzip/zlib and XOR", []),
    "binwalk_scan": ("Find and extract embedded archives/firmware", [("binwalk",)]),
    "exif_scan": ("Read image and document metadata", [("exiftool",)]),
    "rsactftool": ("Attack weak RSA keys and decrypt ciphertext", [config.TOOL_BIN["rsactftool"]]),
    "zeratool_pwn": ("Attempt automatic ELF exploitation", [config.TOOL_BIN["zeratool"]]),
    "stegseek": ("Crack steghide carriers with a wordlist", [config.TOOL_BIN["stegseek"]]),
    "volatility": ("Inspect memory images; symbols may be needed", [config.TOOL_BIN["volatility"]]),
    "web_sqlmap": ("Test SQL injection at CYF_URL", [config.TOOL_BIN["sqlmap"]]),
    "web_ffuf": ("Discover web paths at CYF_URL; curl fallback needs ffuf too", [config.TOOL_BIN["ffuf"], ("curl",)]),
    "net_probe": ("Read a TCP banner from CYF_HOST:CYF_PORT", []),
    "reverse_analyze": ("Inspect ELF code and data sections", [config.TOOL_BIN["radare2"], ("objdump",)]),
    "zsteg_scan": ("Inspect PNG/BMP least-significant-bit payloads", [config.TOOL_BIN["zsteg"]]),
    "pcap_analyze": ("Reassemble capture streams and export HTTP objects", [config.TOOL_BIN["tshark"]]),
    "jwt_attack": ("Crack weak JWT secrets, forge claims, optionally replay", [config.TOOL_BIN["jwt_tool"]]),
    "nuclei_scan": ("Scan CYF_URL with installed vulnerability templates", [config.TOOL_BIN["nuclei"]]),
    "sherlock_search": ("Find accounts for CYF_USERNAME; requires internet", [config.TOOL_BIN["sherlock"]]),
}


def describe_tools(check=False):
    lines = ["DecafShot: 18 engine adapters (catalog recommendations are a separate list)."]
    for tool in REGISTRY:
        description, groups = CAPABILITIES[tool.name]
        lines.append(f"{tool.name:18} {description}")
        if check:
            for group in groups:
                found = next((shutil.which(n) for n in group if shutil.which(n)), None)
                lines.append(f"  {'FOUND ' + found if found else 'MISSING ' + ' / '.join(group)}")
            if not groups:
                lines.append("  BUILT-IN (Python standard library)")
    if check:
        for name in ("STEGSEEK_WORDLIST", "FFUF_WORDLIST", "JWT_WORDLIST"):
            value = getattr(config, name)
            lines.append(f"{name}: {'FOUND' if Path(value).is_file() else 'MISSING'} {value}")
        for name in ("WEB_URL", "PWN_HOST", "PWN_PORT", "OSINT_USERNAME"):
            lines.append(f"{name}: {'set' if getattr(config, name) else 'not set'}")
        lines.append("Discovery only: FOUND does not verify versions, patches, symbols, templates or solve capability.")
    lines.append("Full commands and category examples: python 3_flag_hunter/run.py --guide")
    return "\n".join(lines)
