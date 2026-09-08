#!/usr/bin/env python3
"""
batch.py — run the engine over a whole folder of challenges and produce the
results table for your paper's evaluation section.

Layout it expects (either works):
  A) challenges/<category>/<challenge>/...      <- category from folder name
  B) challenges/<challenge>/...                 <- category auto-detected (misc)

For each challenge it runs hunt(), then prints a table and writes results.csv:
  challenge | category | difficulty | solved | steps | solved_by | time_s | flag

Usage:
  python batch.py ./challenges --difficulty medium
  python batch.py ./challenges --difficulty medium --csv out.csv
"""
import argparse, csv, sys, time
from pathlib import Path
from cyf import hunt

KNOWN_CATS = {"web", "crypto", "reverse", "pwn", "forensics",
              "stego", "osint", "hardware", "misc"}


def find_challenges(root: Path):
    """Yield (challenge_path, category). A challenge = a leaf dir with files,
    or a single file directly under root."""
    for p in sorted(root.iterdir()):
        if p.is_file():
            yield p, "misc"
        elif p.is_dir() and p.name in KNOWN_CATS:
            # category folder -> each subdir/file is a challenge of that category
            for c in sorted(p.iterdir()):
                yield c, p.name
        elif p.is_dir():
            yield p, "misc"


def main():
    ap = argparse.ArgumentParser(description="Batch-run CYF Flag Hunter")
    ap.add_argument("folder", help="folder of challenges")
    ap.add_argument("--difficulty", default="medium",
                    choices=["easy", "medium", "hard"])
    ap.add_argument("--csv", default="results.csv")
    args = ap.parse_args()

    root = Path(args.folder)
    if not root.exists():
        sys.exit(f"no such folder: {root}")

    rows = []
    for path, category in find_challenges(root):
        t0 = time.time()
        ev, _ = hunt(category, args.difficulty, str(path), verbose=False)
        dt = round(time.time() - t0, 2)
        rows.append({
            "challenge": path.name,
            "category": category,
            "difficulty": args.difficulty,
            "solved": "yes" if ev.flag else "no",
            "steps": ev.steps,
            "solved_by": ev.solved_by or "-",
            "time_s": dt,
            "flag": ev.flag or "-",
        })

    # ---- print table ----
    if not rows:
        sys.exit("no challenges found.")
    w = {k: max(len(k), *(len(str(r[k])) for r in rows)) for k in rows[0]}
    hdr = "  ".join(f"{k:<{w[k]}}" for k in rows[0])
    print("\n" + hdr)
    print("-" * len(hdr))
    for r in rows:
        print("  ".join(f"{str(r[k]):<{w[k]}}" for k in r))

    # ---- summary ----
    n = len(rows); solved = sum(r["solved"] == "yes" for r in rows)
    avg_steps = round(sum(r["steps"] for r in rows) / n, 1)
    print("-" * len(hdr))
    print(f"solved {solved}/{n} ({100*solved//n}%)   avg steps {avg_steps}")

    # per-category breakdown
    cats = {}
    for r in rows:
        c = cats.setdefault(r["category"], [0, 0])
        c[0] += 1; c[1] += r["solved"] == "yes"
    print("by category:", "  ".join(f"{k} {v[1]}/{v[0]}" for k, v in cats.items()))

    # ---- write csv ----
    with open(args.csv, "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=list(rows[0]))
        wr.writeheader(); wr.writerows(rows)
    print(f"\nwrote {args.csv}")


if __name__ == "__main__":
    main()
