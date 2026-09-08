#!/usr/bin/env python3
"""
run.py — command-line entry.

    python run.py --category forensics --difficulty medium --path ./chal.bin

If you have the classifier from the other project, pipe its category in;
otherwise pass --category by hand.
"""
import argparse
from cyf import hunt


def main():
    ap = argparse.ArgumentParser(description="CYF Flag Hunter (deterministic CTF engine)")
    ap.add_argument("--path", required=True, help="challenge file")
    ap.add_argument("--category", default="misc",
                    help="web/crypto/reverse/pwn/forensics/stego/osint/hardware/misc")
    ap.add_argument("--difficulty", default="medium",
                    choices=["easy", "medium", "hard"])
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    ev, _ = hunt(args.category, args.difficulty, args.path,
                 verbose=not args.quiet)
    if ev.flag:
        print(args.quiet and ev.flag or "")
    else:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
