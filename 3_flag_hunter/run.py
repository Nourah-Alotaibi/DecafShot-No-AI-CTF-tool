#!/usr/bin/env python3
"""
run.py — command-line entry.

    python run.py --category forensics --difficulty medium --path ./chal.bin

If you have the classifier from the other project, pipe its category in;
otherwise pass --category by hand.
"""
import argparse
from pathlib import Path
from cyf import hunt


def main():
    ap = argparse.ArgumentParser(description="Decaf Flag Hunter (deterministic CTF engine)")
    ap.add_argument("--path", help="challenge file or directory")
    ap.add_argument("--category", default="misc",
                    choices=["web", "crypto", "reverse", "pwn", "forensics", "stego", "osint", "hardware", "misc"],
                    help="web/crypto/reverse/pwn/forensics/stego/osint/hardware/misc")
    ap.add_argument("--difficulty", default="medium",
                    choices=["easy", "medium", "hard"])
    ap.add_argument("--quiet", action="store_true")
    info = ap.add_mutually_exclusive_group()
    info.add_argument("--guide", action="store_true", help="show the complete command and CTF use-case guide")
    info.add_argument("--list-tools", action="store_true", help="list all engine adapters and their uses")
    info.add_argument("--doctor", action="store_true", help="check local dependencies without running tools or contacting targets")
    args = ap.parse_args()

    if args.guide:
        print((Path(__file__).resolve().parents[1] / "HELP.md").read_text(encoding="utf-8"))
        return
    if args.list_tools or args.doctor:
        from cyf.help import describe_tools
        print(describe_tools(check=args.doctor))
        return
    if not args.path:
        ap.error("--path is required to hunt; use --guide for examples")
    if not Path(args.path).exists():
        ap.error(f"challenge path does not exist: {args.path}")

    ev, _ = hunt(args.category, args.difficulty, args.path,
                 verbose=not args.quiet)
    if ev.flag:
        print(args.quiet and ev.flag or "")
    else:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
