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

    sudo apt install file binutils binwalk exiftool tshark radare2  # strings is in binutils
    gem install zsteg
    pip install volatility3 sqlmap zeratool   # then: ./patches/apply_zeratool_fixes.sh
    go install github.com/ffuf/ffuf/v2@latest
    git clone https://github.com/RsaCtfTool/RsaCtfTool && pip install -r RsaCtfTool/requirements.txt

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
                          exif/RsaCtfTool/Zeratool/stegseek/zsteg/volatility/
                          sqlmap/ffuf/net_probe/radare2+objdump/tshark); each
                          skips cleanly if its binary isn't installed
- `cyf/flag_miner.py`  — regex + bounded decode ladder (base64/32/hex/rot13/
                          rot47/atbash/urldecode/morse/gzip+zlib/xor1/xor_crib)
- `cyf/engine.py`      — the orchestration loop (the contribution)
- `run.py`             — CLI, `batch.py` — corpus evaluation (see `challenges/`)

## Current real coverage (measured, not claimed)

`python batch.py ./challenges --difficulty medium` against the bundled test
corpus: 13/13 solved (forensics x3, stego x2, crypto x4, hardware/osint/pwn/
reverse x1 each). web isn't in that corpus because it's a network-target
challenge, not a file — validated separately against a local test server
(see commit history). This is "each wired capability provably works end to
end," not a claim about solve rate on real competition difficulty — build
`challenges/` out with harder, real challenges to get a number that means
that (see "What this can't do yet" below for exactly where the ceiling is).

## Multi-stage challenges: extraction chains, not just one flag regex sweep

Real medium+ challenges are rarely one technique — a stego image hides a
zip, the zip has an encrypted blob, decrypting it reveals a binary to
reverse. Early on, an extracted/decoded file just had its raw bytes dumped
into one undifferentiated text blob, which only helped if the *final*
payload happened to already be plain-text. `_ingest_extracted()` in
`tools.py` fixes this: anything a tool pulls out (binwalk extraction, a
tshark HTTP object export, ...) gets classified exactly like `FileId` would
— signals set, added to `ev.extra_files` — so every subsequent tool's
`_all_files(ev)` sees it too. Verified end to end:
`tests/test_engine_smoke.py::test_recursive_extraction_pcap_to_gzip_object`
exercises a pcap → exported gzip object → decompressed → flag chain with
no binwalk involved, isolating the actual code path.

Known limitation: a tool that already ran (`ev.ran`) won't automatically
retry just because a relevant file showed up *afterward* — that would need
per-file re-entry tracking, not just per-tool. In practice this still
covers the common case since extraction tools tend to rank early.

## What this can't do yet (the honest ceiling)

Wiring more tools raises the ceiling toward "medium," not "hard" — some of
what defines hard-tier is structurally out of reach for a no-generative-
model system, not a missing adapter:
- **Custom crypto schemes** (a bespoke script implementing a novel
  construction) need someone to read the math and derive the attack.
  `RsaCtfTool`'s roster only covers known weaknesses in *standard* RSA.
- **Heap exploitation** (tcache poisoning, house-of-X) needs a bespoke
  primitive built from the binary's specific allocator behavior — even
  angr-based AEG research tools still struggle here.
- **Leak-then-second-stage pwn** (info-leak → compute base → build a
  ROP chain) is a fundamentally different two-phase pipeline `Zeratool`'s
  single-shot point-to-win doesn't attempt. `ropper`/`one_gadget` are
  installed and unwired — the missing piece is the orchestration logic
  connecting a leak to a chain-builder, not the tools themselves.
- **Physical hardware** (real UART/JTAG wiring, RF capture) can't be
  automated in software at all.

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
