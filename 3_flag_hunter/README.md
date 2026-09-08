# CYF Flag Hunter — deterministic adaptive CTF engine

A deterministic CTF investigation engine. It picks the next security tool to
run based on a hand-authored score and the evidence gathered so far — no
generative model, no internet needed at solve time. The adaptivity comes from
evidence changing the scores, not from learning.

This is the "empty quadrant": **multi-category + adaptive + no generative
model**. Existing tools cover only two of the three (Zeratool/autorop =
adaptive+non-generative but pwn only; Katana = multi-category+non-generative
but fixed order; autonomous solving agents = multi-category+adaptive but rely
on a generative model).

## Setup

    python3 --version          # 3.10+
    # no pip deps for the core engine — stdlib only

Optional real tools (the adapters use them if present, skip cleanly if not):

    sudo apt install file binutils binwalk exiftool   # strings is in binutils

## Run

    python run.py --path ./challenge.txt --category crypto --difficulty easy

    # categories: web crypto reverse pwn forensics stego osint hardware misc
    # difficulty: easy | medium | hard  (controls step budget + timeouts)

You'll see the ranking recomputed at every step, the chosen tool, and the
evidence it added — then the flag if found.

## How it fits together

    classify()  ->  category + difficulty        (from the classifier project)
         |
         v
    ENGINE loop (engine.py):
       rank tools (ranker.py) = base_weight[category] x applicable(evidence)
       run top tool (tools.py) -> writes facts/signals into evidence.py
       flag miner (flag_miner.py) sweeps for CYF{...} + decode ladder
       repeat -> ranking changes because evidence changed  = adaptive, no generative model

## Files

- `cyf/config.py`      — flag regex, difficulty budgets, tool base weights (tune here)
- `cyf/catalog.py`     — blends 2_tool_catalog's scraped popularity data into weights
- `cyf/evidence.py`    — the blackboard (facts, signals, visited tools)
- `cyf/ranker.py`      — the deterministic action ranker (the "brain")
- `cyf/tools.py`       — tool adapters, all real (file/strings/binwalk+extract/
                          exif/RsaCtfTool/Zeratool/stegseek/volatility/sqlmap/
                          ffuf/net_probe/radare2+objdump); each skips cleanly
                          if its binary isn't installed
- `cyf/flag_miner.py`  — regex + bounded decode ladder (base64/32/hex/rot13/
                          rot47/atbash/urldecode/morse/gzip+zlib/xor1/xor_crib)
- `cyf/engine.py`      — the orchestration loop (the contribution)
- `run.py`             — CLI, `batch.py` — corpus evaluation (see `challenges/`)

## Current real coverage (measured, not claimed)

`python batch.py ./challenges --difficulty medium` against the bundled test
corpus: 9/9 solved, one real working adapter chain per category (crypto,
forensics, hardware, osint, reverse, stego). web/pwn aren't in that corpus
because they're network-target challenges, not files — validated separately
against local test servers (see the session notes / commit history). This is
"each wired capability provably works end to end," not a claim about solve
rate on real competition difficulty — build `challenges/` out with harder,
real challenges to get a number that means that.

Optional environment for the network-facing adapters (all skip cleanly if unset):

    CYF_URL=http://target/path   python run.py --category web  ...   # sqlmap/ffuf
    CYF_HOST=1.2.3.4 CYF_PORT=1337 python run.py --category pwn ...  # net_probe

## pwn / Zeratool — requires a patch to actually work

`pip install zeratool` on its own is broken for real use, two separate ways:

1. **Hard crash**: its `puts`/shellcode hooks call `state.solver.BVV(...)`,
   an API current `angr`/`claripy` removed — every run crashes with
   `AttributeError: 'SimSolver' object has no attribute 'BVV'`.
2. **Silent exploit failure**: even once that's fixed, its "point to win"
   technique jumps straight at the win function with no stack-alignment
   pad. On modern glibc, a win function that calls `system()`/`printf()`
   needs a 16-byte-aligned stack (SSE `movaps`) — angr can't predict this
   because that call is a stubbed SimProcedure, not real execution — so a
   *correctly*-found offset and address still segfaults at delivery time.
   This is an extremely common real-world CTF shape, not an edge case.

Both are fixed in `patches/zeratool-fixes.patch` (verified: turns a hard
crash into a correct, automatic, zero-manual-intervention flag capture on
`challenges/pwn/ret2win`). Apply once after installing zeratool:

    pip install zeratool
    ./patches/apply_zeratool_fixes.sh

Without this, `cyf/tools.py`'s `Zeratool` adapter will mostly fail even on
genuinely solvable challenges — this isn't optional polish.

## Extending

- New tool: subclass `Tool`, set `applicable()` + `run()`, add to `REGISTRY`,
  give it a row in `BASE_WEIGHTS`.
- New signal: have a tool `ev.add_signal("thing")`, then read it in other tools'
  `applicable()` to raise their score when that evidence appears.
- Different event: change `FLAG_REGEX` in config.py.
