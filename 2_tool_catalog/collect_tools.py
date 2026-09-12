#!/usr/bin/env python3
"""
collect_tools.py — build a ranked, data-driven CTF tool catalog from GitHub.

For each CTF category it runs a set of GitHub search queries, merges the
results, dedupes by repo, ranks by a score (stars + recency), and writes:
  - tools_catalog.json   (full structured data, feeds classifier.py TOOLS)
  - tools_catalog.md     (human-readable, per category)

No generative model. Just the GitHub search API. Regenerate whenever you want fresh rankings.

Auth (optional but recommended — lifts rate limit 10->30 req/min):
    export GITHUB_TOKEN=ghp_xxx
"""
from __future__ import annotations
import argparse, json, os, re, time, urllib.parse, urllib.request, sys
from pathlib import Path
from datetime import datetime, timezone

API = "https://api.github.com/search/repositories"
TOKEN = os.environ.get("GITHUB_TOKEN", "")

# Per-category search queries. Mix of: known tool names (precision) and
# topic/keyword searches (recall for tools we don't know yet).
QUERIES = {
    "web": [
        "ctf web exploitation tool", "web fuzzer", "sql injection tool",
        "topic:web-security topic:pentesting",
    ],
    "crypto": [
        "ctf crypto tool", "rsa attack tool", "cipher solver",
        "topic:cryptography topic:ctf",
    ],
    "reverse": [
        "reverse engineering tool", "decompiler", "disassembler",
        "topic:reverse-engineering",
    ],
    "pwn": [
        "binary exploitation tool", "rop gadget", "pwntools exploit",
        "topic:pwn topic:exploit",
    ],
    "forensics": [
        "ctf forensics tool", "memory forensics", "pcap analysis tool",
        "file carving tool", "topic:forensics",
    ],
    "stego": [
        "steganography tool", "ctf stego", "lsb steganography",
        "topic:steganography",
    ],
    "osint": [
        "osint tool", "username search tool", "email osint",
        "topic:osint",
    ],
    "hardware": [
        "firmware analysis tool", "ctf hardware tool", "sdr signal tool",
        "topic:firmware topic:iot-security",
    ],
}

# Repos that are meta/lists, not runnable tools — keep separately.
META_KEYWORDS = ("awesome", "cheat", "list-of", "resources", "roadmap",
                 "writeup", "write-up", "notes")

# Hard denylist: obvious non-CTF-tool noise that keyword search drags in.
DENY_SUBSTR = (
    "code-review", "code review", "gpt4free", "website-cloner", "librepods",
    "worldmonitor", "china-dictatorship", ".config", ".github", "singlefile",
    "course", "tutorial tutorial", "dictatorship", "news aggregation",
)

# Relevance gate: a repo must carry at least one security/CTF signal word
# somewhere in name + description + topics, or it's dropped.
RELEVANCE_SIGNALS = (
    "ctf", "exploit", "security", "pentest", "vulnerab", "hacking", "recon",
    "fuzz", "crypto", "cipher", "rsa", "reverse", "decompil", "disassembl",
    "binary", "rop", "pwn", "forensic", "memory", "pcap", "carv", "steg",
    "osint", "firmware", "malware", "attack", "payload", "injection",
)

# Canonical tools that should always win the top slots per category
# (name, repo url). GitHub search fills the discovery tail below these.
CANONICAL = {
    "web":       [("ffuf", "https://github.com/ffuf/ffuf"),
                  ("sqlmap", "https://github.com/sqlmapproject/sqlmap"),
                  ("nuclei", "https://github.com/projectdiscovery/nuclei")],
    "crypto":    [("RsaCtfTool", "https://github.com/RsaCtfTool/RsaCtfTool"),
                  ("Ciphey", "https://github.com/bee-san/Ciphey")],
    "reverse":   [("ghidra", "https://github.com/NationalSecurityAgency/ghidra"),
                  ("radare2", "https://github.com/radareorg/radare2"),
                  ("angr", "https://github.com/angr/angr")],
    "pwn":       [("pwntools", "https://github.com/Gallopsled/pwntools"),
                  ("gef", "https://github.com/hugsy/gef"),
                  ("pwndbg", "https://github.com/pwndbg/pwndbg")],
    "forensics": [("volatility3", "https://github.com/volatilityfoundation/volatility3"),
                  ("wireshark", "https://github.com/wireshark/wireshark")],
    "stego":     [("zsteg", "https://github.com/zed-0xff/zsteg"),
                  ("stegseek", "https://github.com/RickdeJager/stegseek")],
    "osint":     [("sherlock", "https://github.com/sherlock-project/sherlock"),
                  ("maigret", "https://github.com/soxoj/maigret"),
                  ("spiderfoot", "https://github.com/smicallef/spiderfoot")],
    "hardware":  [("binwalk", "https://github.com/ReFirmLabs/binwalk"),
                  ("FACT_core", "https://github.com/fkie-cad/FACT_core")],
}


def gh_search(query: str, per_page: int = 12) -> list[dict]:
    params = urllib.parse.urlencode({
        "q": query, "sort": "stars", "order": "desc", "per_page": per_page,
    })
    req = urllib.request.Request(f"{API}?{params}")
    # mercy-preview returns the `topics` array used by the relevance filter
    req.add_header("Accept", "application/vnd.github.mercy-preview+json")
    req.add_header("User-Agent", "ctf-tool-collector")
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                remaining = r.headers.get("X-RateLimit-Remaining", "?")
                data = json.loads(r.read())
                return data.get("items", []), remaining
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):          # rate limited
                wait = 8 * (attempt + 1)
                print(f"    rate-limited, waiting {wait}s...", file=sys.stderr)
                time.sleep(wait)
                continue
            print(f"    HTTP {e.code} on '{query}'", file=sys.stderr)
            return [], "?"
        except Exception as ex:
            print(f"    error on '{query}': {ex}", file=sys.stderr)
            return [], "?"
    return [], "?"


def months_since(iso: str) -> float:
    try:
        d = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - d).days / 30.0
    except Exception:
        return 999.0


def score(repo: dict) -> float:
    """Stars carry the signal; penalize stale repos, reward recent pushes."""
    import math
    stars = repo.get("stargazers_count", 0)
    stale = months_since(repo.get("pushed_at", ""))
    recency = 1.0 if stale <= 12 else (0.7 if stale <= 36 else 0.4)
    return round(math.log10(stars + 1) * 10 * recency, 2)


def is_meta(repo: dict) -> bool:
    name = (repo.get("name", "") + " " + (repo.get("description") or "")).lower()
    return any(k in name for k in META_KEYWORDS)


def blob_of(repo: dict) -> str:
    return " ".join([
        repo.get("name", ""), repo.get("description") or "",
        " ".join(repo.get("topics", []) or []),
    ]).lower()


def is_denied(repo: dict) -> bool:
    blob = blob_of(repo)
    return any(d in blob for d in DENY_SUBSTR) or bool(re.search(
        r"\b(?:llms?|gpt\w*|chatgpt|openai|anthropic|claude|ollama|langchain|generative[ -]?ai)\b|"
        r"large language model|ai[ -]powered|ai agents?", blob))


def is_relevant(repo: dict) -> bool:
    return any(s in blob_of(repo) for s in RELEVANCE_SIGNALS)


def norm(repo: dict) -> dict:
    return {
        "name": repo["name"],
        "full_name": repo["full_name"],
        "url": repo["html_url"],
        "stars": repo.get("stargazers_count", 0),
        "language": repo.get("language"),
        "description": (repo.get("description") or "").strip(),
        "pushed_at": repo.get("pushed_at", "")[:10],
        "months_stale": round(months_since(repo.get("pushed_at", "")), 1),
        "meta": is_meta(repo),
        "score": score(repo),
    }


def fetch_repo(full_name: str) -> dict | None:
    """Fetch a single repo (for canonical seeds) so they always appear."""
    req = urllib.request.Request(f"https://api.github.com/repos/{full_name}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "ctf-tool-collector")
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())
    except Exception:
        return None


def collect(per_category: int = 8):
    catalog = {}
    claimed = set()   # full_name already assigned to a category (dedupe)

    for cat, queries in QUERIES.items():
        print(f"[{cat}] {len(queries)} queries...", file=sys.stderr)
        bucket = {}

        # 1. canonical seeds first — pinned, always present
        for _, url in CANONICAL.get(cat, []):
            fn = url.split("github.com/")[-1]
            if fn in claimed:
                continue
            raw = fetch_repo(fn)
            if raw:
                rec = norm(raw)
                rec["pinned"] = True
                bucket[fn] = rec
                claimed.add(fn)
            time.sleep(1.2)

        # 2. discovery via search — filtered
        for q in queries:
            items, remaining = gh_search(q)
            for repo in items:
                fn = repo["full_name"]
                if fn in bucket or fn in claimed:
                    continue
                if is_denied(repo) or not is_relevant(repo):
                    continue
                rec = norm(repo)
                rec["pinned"] = False
                bucket[fn] = rec
            time.sleep(2.2)

        # rank: pinned canonical on top, then by score
        ranked = sorted(bucket.values(),
                        key=lambda r: (r.get("pinned", False), r["score"]),
                        reverse=True)
        tools = [r for r in ranked if not r["meta"]][:per_category]
        for t in tools:
            claimed.add(t["full_name"])
        meta = [r for r in ranked if r["meta"]][:3]
        catalog[cat] = {"tools": tools, "meta_lists": meta}
        print(f"    -> {len(tools)} tools, {len(meta)} meta (rl remaining {remaining})",
              file=sys.stderr)
    return catalog


def write_outputs(catalog: dict, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "tools_catalog.json").write_text(json.dumps(catalog, indent=2), encoding="utf-8")

    lines = ["# CTF Tool Catalog (auto-collected from GitHub)\n",
             f"_Generated {datetime.now().strftime('%Y-%m-%d')} — ranked by "
             "stars x recency. Regenerate with `python collect_tools.py`._\n"]
    for cat, block in catalog.items():
        lines.append(f"\n## {cat}\n")
        lines.append("| Tool | Stars | Lang | Last push | Repo |")
        lines.append("|------|------:|------|-----------|------|")
        for t in block["tools"]:
            desc = t["description"][:70]
            lines.append(f"| **{t['name']}** — {desc} | {t['stars']:,} | "
                         f"{t['language'] or '-'} | {t['pushed_at']} | "
                         f"[link]({t['url']}) |")
        if block["meta_lists"]:
            metas = ", ".join(f"[{m['name']}]({m['url']})" for m in block["meta_lists"])
            lines.append(f"\n_Meta/awesome lists:_ {metas}\n")
    (outdir / "tools_catalog.md").write_text("\n".join(lines), encoding="utf-8")

    # a slim TOOLS dict ready to paste into classifier.py
    slim = {cat: [t["name"] for t in block["tools"][:5]]
            for cat, block in catalog.items()}
    (outdir / "TOOLS_snippet.py").write_text(
        "# paste into classifier.py — top 5 per category, auto-ranked\n"
        "TOOLS = " + json.dumps(slim, indent=4), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description="Refresh the GitHub CTF tool catalog (requires internet)")
    ap.add_argument("count", nargs="?", type=int, default=8, help="tools per category (default: 8)")
    ap.add_argument("--outdir", type=Path, default=Path(__file__).resolve().parent,
                    help="output directory; defaults to the catalog consumed by the engine")
    args = ap.parse_args()
    if args.count < 1:
        ap.error("count must be positive")
    cat = collect(per_category=args.count)
    write_outputs(cat, args.outdir)
    print(f"\nDone. Wrote {args.outdir} (json + md + TOOLS_snippet.py)", file=sys.stderr)


if __name__ == "__main__":
    main()
