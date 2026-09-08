#!/usr/bin/env python3
"""
scrape_ctf_writeups.py — pulls REAL labeled training data for the ML stage
from public CTF write-up repos on GitHub, closing the gap the project's own
docs flagged: "_starter_dataset() ... Replace/extend with scraped CTFtime +
picoCTF data" (classifier.py) and the RELATED_WORK.md honesty note that the
hand-written seed set is a data-size artifact, not a finished dataset.

Method (no generative model — plain heuristics, like everything else here):
  1. Get each seed repo's full file tree in ONE API call (git trees API,
     recursive=1) and find every README.md. Early version of this script
     tried to infer category from DIRECTORY names (crypto/, web/, ...) —
     that failed on every repo actually tried: real aggregators organize
     by competition event and challenge NAME (e.g. "dyrpto", "sidhe"), not
     category, so there was no signal there at all.
  2. The real, load-bearing signal turned out to be the title line most of
     these writeups share, copied from ctftime.org's own listing format:
         # challenge_name (crypto, 250p, 66 solved)
     Regex-extract the parenthetical, match it against a category/synonym
     table. This generalizes across repos/authors far better than any
     directory convention did.
  3. Fetch each README's raw content via its download_url — plain HTTPS,
     not an API call, so it doesn't touch the 60/hour unauthenticated API
     budget no matter how many files a repo has.
  4. Clean each writeup down to a short label-worthy snippet (title +
     first paragraph — the register real challenge descriptions are
     written in, not a multi-page walkthrough).

Rate-limit aware: unauthenticated core API calls are capped at 60/hour, and
this script uses exactly 2 per repo (repo info for the default branch, then
one recursive tree listing) regardless of repo size. Set GITHUB_TOKEN to
raise that budget; the free raw-fetch side is unaffected either way.

Usage:
    python3 scrape_ctf_writeups.py                  # scrape, write dataset
    python3 scrape_ctf_writeups.py --max-repos 3     # smaller run
    python3 scrape_ctf_writeups.py --dry-run         # print counts only
"""
from __future__ import annotations
import argparse, json, os, re, sys, time, urllib.error, urllib.request

API = "https://api.github.com"
HEADERS = {"Accept": "application/vnd.github+json", "User-Agent": "cyf-scraper"}
if os.environ.get("GITHUB_TOKEN"):
    HEADERS["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"

OUT_PATH = os.path.join(os.path.dirname(__file__), "scraped_dataset.json")

# Known, well-maintained CTF write-up aggregator repos. A fixed seed list
# rather than a fresh search each run, so results are reproducible.
SEED_REPOS = [
    "TFNS/writeups",
    "balsn/ctf_writeup",
    "p4-team/ctf",
    "ctfs/write-ups-2017",
    "ctfs/write-ups-2016",
    "Crypto-Cat/CTF",
    # w181496/CTF-writeups and Osirisctf/osiris-ctf-writeups 404'd (renamed
    # or deleted) as of 2026-09 — replaced with these. Note not every repo
    # uses the "(category, Npts, N solved)" title convention (perfectblue's
    # doesn't, for example) — those just yield 0 examples harmlessly rather
    # than crashing, so it's fine to try more candidates speculatively.
    "Ignitetechnologies/Vulnhub-CTF-Writeups",
    "Dvd848/CTFs",
    "bl4de/ctf",
    "susers/Writeups",
]

# category -> synonyms to match inside the "(category, Npts, ...)" title
# parenthetical (case-insensitive, matched as a whole word/phrase).
CATEGORY_SYNONYMS = {
    "web": {"web", "web exploitation", "webexploitation"},
    "crypto": {"crypto", "cryptography"},
    "pwn": {"pwn", "pwnable", "binary exploitation", "exploitation", "bin"},
    "reverse": {"reverse", "reversing", "re", "reverse engineering"},
    "forensics": {"forensics", "forensic", "network", "networking"},
    "stego": {"stego", "steganography", "steg"},
    "osint": {"osint", "recon"},
    "hardware": {"hardware", "iot", "embedded", "radio", "rf"},
}
SYNONYM_TO_CAT = {s: c for c, syns in CATEGORY_SYNONYMS.items() for s in syns}

TITLE_RE = re.compile(r"^#+\s*.+?\(([^)]*)\)", re.M)


def _get_json(url, retries=2):
    req = urllib.request.Request(url, headers=HEADERS)
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                remaining = r.headers.get("X-RateLimit-Remaining")
                if remaining is not None:
                    print(f"    [api calls remaining: {remaining}]", file=sys.stderr)
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 403 and attempt < retries:
                print("    rate limited, sleeping 5s...", file=sys.stderr)
                time.sleep(5)
                continue
            if e.code == 404:
                return None
            raise
    return None


def _get_raw(url, max_bytes=20000):
    req = urllib.request.Request(url, headers={"User-Agent": "cyf-scraper"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read(max_bytes).decode(errors="replace")


def _category_from_title(text):
    m = TITLE_RE.search(text)
    if not m:
        return None
    paren = m.group(1).lower()
    parts = [p.strip() for p in re.split(r"[,/]", paren)]
    for p in parts:
        p = re.sub(r"\s+", " ", p).strip()
        if p in SYNONYM_TO_CAT:
            return SYNONYM_TO_CAT[p]
    return None


def _clean_snippet(text, max_chars=600):
    """A challenge description is a paragraph, not a multi-page walkthrough
    — trim to the register classify() is actually used on."""
    text = re.sub(r"```.*?```", " ", text, flags=re.S)     # code blocks
    text = re.sub(r"!\[.*?\]\(.*?\)", " ", text)             # images
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)     # [text](link)
    text = re.sub(r"^#+\s*", "", text, flags=re.M)           # md headers
    text = re.sub(r"[*_`>#]", " ", text)
    text = re.sub(r"https?://\S+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_chars]


def scrape_repo(repo, max_readmes=120):
    info = _get_json(f"{API}/repos/{repo}")
    if not info:
        print(f"    couldn't fetch repo info for {repo}", file=sys.stderr)
        return
    branch = info.get("default_branch", "master")
    tree = _get_json(f"{API}/repos/{repo}/git/trees/{branch}?recursive=1")
    if not tree or tree.get("truncated") and not tree.get("tree"):
        print(f"    couldn't fetch tree for {repo}", file=sys.stderr)
        return
    readmes = [e for e in tree.get("tree", [])
               if e["type"] == "blob" and e["path"].lower().endswith(("readme.md", "writeup.md"))]
    print(f"    {len(readmes)} README/writeup files found", file=sys.stderr)
    fetched = 0
    for entry in readmes:
        if fetched >= max_readmes:
            break
        raw_url = f"https://raw.githubusercontent.com/{repo}/{branch}/{entry['path']}"
        try:
            content = _get_raw(raw_url)
        except Exception:
            continue
        fetched += 1
        category = _category_from_title(content)
        if not category:
            continue
        # title + first real paragraph after it, for a realistic snippet
        body = TITLE_RE.sub("", content, count=1)
        snippet = _clean_snippet(content.split("\n", 1)[0] + ". " + body)
        if len(snippet) >= 40:
            yield snippet, category, repo


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-repos", type=int, default=len(SEED_REPOS))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    dataset = []
    for repo in SEED_REPOS[: args.max_repos]:
        print(f"[+] scanning {repo}", file=sys.stderr)
        try:
            for text, category, source in scrape_repo(repo):
                dataset.append({"text": text, "category": category, "source": source})
        except Exception as e:
            print(f"    skipping {repo}: {e}", file=sys.stderr)
            continue

    by_cat = {}
    for row in dataset:
        by_cat[row["category"]] = by_cat.get(row["category"], 0) + 1
    print(f"\nscraped {len(dataset)} labeled examples:", file=sys.stderr)
    for cat, n in sorted(by_cat.items()):
        print(f"  {cat:10} {n}", file=sys.stderr)

    if not args.dry_run:
        with open(OUT_PATH, "w") as f:
            json.dump(dataset, f, indent=1)
        print(f"\nwrote {OUT_PATH}", file=sys.stderr)


if __name__ == "__main__":
    main()
