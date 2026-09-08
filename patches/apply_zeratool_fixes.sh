#!/usr/bin/env bash
# Applies zeratool-fixes.patch to the installed zeratool==2.2 package.
#
# Why this exists: the pip-installed zeratool 2.2 is broken against current
# angr/claripy (a real upstream bug, not specific to this box) and its
# "point to win" technique has no stack-alignment fallback, so it can't
# actually deliver a payload when the win function calls something like
# system() that needs a 16-byte-aligned stack on modern glibc — a very
# common real-world CTF shape. Also fixes a crash in its format-string
# detector (dereferenced a None result). All three fixed here. Without
# this patch, cyf/tools.py's Zeratool adapter will mostly fail even on
# solvable challenges. See 3_flag_hunter/README.md's "pwn / Zeratool"
# section — including the honest limitation these DON'T fix: gadget-poor
# modern binaries (no pop-rdi anywhere) still block its ROP-chain builder,
# and format-string detection can still legitimately report "not found."
set -euo pipefail

PKG_DIR="$(python3 -c 'import zeratool, os; print(os.path.dirname(zeratool.__file__))' 2>/dev/null)"
if [ -z "$PKG_DIR" ]; then
    echo "zeratool isn't installed — pip install zeratool first." >&2
    exit 1
fi

VERSION="$(python3 -c 'import importlib.metadata as m; print(m.version("zeratool"))' 2>/dev/null || echo unknown)"
if [ "$VERSION" != "2.2" ]; then
    echo "warning: installed zeratool is $VERSION, this patch was built against 2.2." >&2
    echo "         it may still apply — if 'patch' fails below, diff by hand." >&2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$PKG_DIR")"

echo "Applying to: $PKG_DIR"
patch -p1 -d "$PARENT_DIR" < "$SCRIPT_DIR/zeratool-fixes.patch"
echo "Done. Verify with: zerapwn.py <a known ret2win binary>"
