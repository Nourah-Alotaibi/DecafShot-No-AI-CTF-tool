#!/usr/bin/env python3
"""
mine_m0x_playbooks.py — extracts (text, category) training pairs from the
m0x-skills-ctfs skill's playbook library (~10,800 real CTF writeup
summaries with clean YAML frontmatter), a much larger real-data source
than scrape_ctf_writeups.py's live GitHub scrape (142 examples).

This is a plain deterministic data extraction — reads YAML frontmatter,
nothing else — not an invocation of that skill's own prompt/agent
behavior. m0x-skills-ctfs is a *prompt library* for an LLM agent to
reason with live; that's a fundamentally different thing from CYF (see
1_classifier/RELATED_WORK.md) and isn't touched here. Only its playbook
*data* is used, copied out into this project — the source skill directory
is read-only to this script, never modified.

Category mapping: m0x's top-level playbook categories are web, crypto,
pwn, reverse, forensics, osint, misc, ai-ml, blockchain, cloud, malware.
CYF's classifier only knows 8: web, crypto, pwn, reverse, forensics,
stego, osint, hardware. web/crypto/pwn/reverse/forensics/osint map
directly; ai-ml/blockchain/cloud/malware have no CYF equivalent and are
dropped; misc is NOT dropped wholesale — it's routed by technique tag,
since that's where m0x files stego and hardware/firmware content instead
of giving them their own top-level folders.

Usage:
    python3 mine_m0x_playbooks.py [path-to-m0x-playbooks-dir]
    python3 mine_m0x_playbooks.py --max-per-category 400
"""
from __future__ import annotations
import argparse, json, os, re, sys
from pathlib import Path

OUT_PATH = os.path.join(os.path.dirname(__file__), "scraped_dataset_m0x.json")

DEFAULT_SEARCH_PATHS = [
    "/home/devcontainers/myownskills2026/myownskills2026/myownskills2026/skills/m0x-skills-ctfs/playbooks",
    os.path.expanduser("~/.claude/skills/m0x-skills-ctfs/playbooks"),
]

DIRECT_MAP = {"web": "web", "crypto": "crypto", "pwn": "pwn",
              "reverse": "reverse", "forensics": "forensics", "osint": "osint"}

# misc-only: route by technique tag since m0x has no dedicated stego/
# hardware folders (CYF needs both).
MISC_TECHNIQUE_ROUTE = [
    (re.compile(r"steg|lsb|spectrogram", re.I), "stego"),
    (re.compile(r"firmware|jtag|uart|hardware|iot|spi|can.?bus|rf\b|sdr\b", re.I), "hardware"),
]

FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.S)


def _parse_frontmatter(text):
    """Tiny hand-rolled YAML-subset parser — these files only ever use
    simple `key: value` and `key: [a, b]` lines, so a real YAML dependency
    isn't worth adding for it."""
    m = FRONTMATTER_RE.match(text)
    if not m:
        return None
    fields = {}
    for line in m.group(1).splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        if val.startswith("[") and val.endswith("]"):
            inner = val[1:-1].strip()
            fields[key] = [v.strip().strip('"\'') for v in inner.split(",") if v.strip()] if inner else []
        else:
            fields[key] = val.strip('"\'')
    return fields


def _category_for(m0x_category, techniques):
    if m0x_category in DIRECT_MAP:
        return DIRECT_MAP[m0x_category]
    if m0x_category == "misc":
        blob = " ".join(techniques).lower()
        for pattern, cyf_cat in MISC_TECHNIQUE_ROUTE:
            if pattern.search(blob):
                return cyf_cat
    return None  # ai-ml/blockchain/cloud/malware, or unrouted misc


def _build_text(fields):
    """Same short, description-like register the rest of the training set
    uses — a title/event/technique summary, not the full solve writeup."""
    title = fields.get("title", "").strip()
    event = fields.get("event", "").strip()
    techniques = fields.get("techniques", [])
    parts = [p for p in (title, event) if p]
    text = " — ".join(parts)
    if techniques:
        text += ". Techniques: " + ", ".join(techniques)
    return text.strip()


def mine(playbooks_dir: Path, max_per_category: int):
    counts = {}
    dataset = []
    for md_file in playbooks_dir.rglob("*.md"):
        if md_file.name.upper().startswith("INDEX"):
            continue
        try:
            raw = md_file.read_text(errors="replace")
        except Exception:
            continue
        fields = _parse_frontmatter(raw)
        if not fields:
            continue
        m0x_cat = fields.get("category", "")
        techniques = fields.get("techniques", [])
        cyf_cat = _category_for(m0x_cat, techniques)
        if not cyf_cat:
            continue
        text = _build_text(fields)
        if len(text) < 15:
            continue
        if counts.get(cyf_cat, 0) >= max_per_category:
            continue
        dataset.append({"text": text, "category": cyf_cat,
                         "source": f"m0x:{fields.get('source', md_file.name)}"})
        counts[cyf_cat] = counts.get(cyf_cat, 0) + 1
    return dataset, counts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("playbooks_dir", nargs="?", default=None)
    ap.add_argument("--max-per-category", type=int, default=400)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.playbooks_dir:
        candidates = [args.playbooks_dir]
    else:
        candidates = DEFAULT_SEARCH_PATHS
    playbooks_dir = next((Path(p) for p in candidates if Path(p).is_dir()), None)
    if playbooks_dir is None:
        print("m0x playbooks directory not found in any of:", file=sys.stderr)
        for p in candidates:
            print(" ", p, file=sys.stderr)
        print("(that's fine — this source is optional; pass a path explicitly "
              "if you have it elsewhere)", file=sys.stderr)
        sys.exit(1)

    print(f"[+] mining {playbooks_dir}", file=sys.stderr)
    dataset, counts = mine(playbooks_dir, args.max_per_category)
    print(f"\nmined {len(dataset)} labeled examples (capped at "
          f"{args.max_per_category}/category):", file=sys.stderr)
    for cat, n in sorted(counts.items()):
        print(f"  {cat:10} {n}", file=sys.stderr)

    if not args.dry_run:
        with open(OUT_PATH, "w") as f:
            json.dump(dataset, f, indent=1)
        print(f"\nwrote {OUT_PATH}", file=sys.stderr)


if __name__ == "__main__":
    main()
