# Historical engine development notes

Archived from the original engine README on 2026-09-12. Installation commands,
machine-specific observations and research-positioning claims below are historical.
Use the [current setup](../README.md), [help](../HELP.md) and
[validation report](VALIDATION.md) for current instructions and measured coverage.

## Original notes

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
    pip install sherlock-project pyjwt
    git clone https://github.com/ticarpi/jwt_tool && pip install -r jwt_tool/requirements.txt
    mkdir -p ~/.local/bin ~/.local/share/jwt_tool
    cp jwt_tool/jwt_tool.py ~/.local/bin/ && chmod +x ~/.local/bin/jwt_tool.py
    cp jwt_tool/*.txt ~/.local/share/jwt_tool/
    # nuclei: this box's Go (1.18) is too old to build it from source —
    # grab a release binary instead (see releases page for the current tag)
    curl -sL "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep -oP '"tag_name": "v\K[^"]+')_linux_amd64.zip" -o /tmp/nuclei.zip
    unzip -o -q /tmp/nuclei.zip nuclei -d ~/.local/bin && chmod +x ~/.local/bin/nuclei
    nuclei -update-templates

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
       flag miner (flag_miner.py) sweeps for FLAG{...} + decode ladder
       repeat -> ranking changes because evidence changed  = adaptive, no generative model

## Files

- `cyf/config.py`      — flag regex, difficulty budgets, tool base weights (tune here)
- `cyf/catalog.py`     — blends 2_tool_catalog's scraped popularity data into weights
- `cyf/evidence.py`    — the blackboard (facts, signals, visited tools)
- `cyf/ranker.py`      — the deterministic action ranker (the "brain")
- `cyf/tools.py`       — tool adapters, all real (file/strings/binwalk+extract/
                          exif/RsaCtfTool/Zeratool/stegseek/zsteg/volatility/
                          sqlmap/ffuf/net_probe/radare2+objdump/tshark/jwt_tool/
                          nuclei/sherlock); each skips cleanly if its binary
                          isn't installed
- `cyf/flag_miner.py`  — regex + bounded decode ladder (base64/32/hex/rot13/
                          rot47/atbash/urldecode/morse/gzip+zlib/xor1/xor_crib)
- `cyf/engine.py`      — the orchestration loop (the contribution)
- `run.py`             — CLI, `batch.py` — corpus evaluation (see `challenges/`)

## Current real coverage (measured, not claimed)

`python batch.py ./challenges --difficulty medium` against the bundled test
corpus: 14/14 solved (crypto x5, forensics x3, stego x2, hardware/osint/pwn/
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

**Update — this used to be a known limitation, now fixed**: a tool that
already ran and found nothing didn't used to reconsider just because a
relevant file showed up *afterward* (e.g. `RsaCtfTool` running before any
`.pem` exists, then a later extraction reveals one). `_ingest_extracted`
now un-marks every file-consuming tool as "already ran" whenever a genuinely
new file appears, so the ranker gives them another shot with the new
evidence — the engine *notices new information and reconsiders old
conclusions*, using one plain rule, not reasoning about which tool might
newly apply. This is the closest thing in this project to "acts like an
agent" while staying strictly rule-based: no model, no learning, just
"new file → stale conclusions about files get cleared." Verified for
real, not just unit-tested in isolation:
`tests/test_engine_smoke.py::test_tool_reconsiders_after_new_file_extracted`
drives the *actual* engine loop end to end — `RsaCtfTool` runs first
(no key file yet), fails cleanly ("no public key file found"), `binwalk_scan`
later extracts a zip containing one, and `RsaCtfTool` gets re-ranked to the
top and solves it on a genuine second attempt, confirmed by asserting the
failed-attempt fact is still in the log alongside the final flag.

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
  ROP chain) — investigated for real, not assumed. `Zeratool` actually
  *has* a full leak+ROP-chain pipeline built in
  (`point_to_ropchain_filter`/`get_leak_rop_chain`, using pwntools' `ROP`
  class), not just the single-shot point-to-win path already wired in.
  Found and fixed a real crash in its format-string detector too
  (`end_state` dereferenced without a None-check; both fixes are in
  `patches/zeratool-fixes.patch`). But testing it against three
  progressively more realistic non-PIE/NX/no-canary binaries (all built
  with this box's current gcc/glibc — not artificially minimal) hit a
  genuine, deep wall: **none had a usable `pop rdi; ret` gadget anywhere**
  — modern glibc (2.34+) dropped the classic `__libc_csu_init` pattern
  that used to guarantee one, and pwntools' `ROP.call()`/`setRegisters()`
  (including its SROP fallback path) can't proceed without it. The
  format-string route sidesteps that gadget requirement entirely (printf's
  own arg-fetching does the register control) — but after fixing the
  crash, zeratool's detector still reported "Can not determine vulnerable
  type" against a textbook, verified-vulnerable `printf(buf)` case.
  `ropper`/`one_gadget` are installed; the missing piece isn't
  orchestration glue, it's gadget availability + working automated
  format-string modeling against this toolchain — a real, current,
  actively-discussed problem in pwn/CTF circles, not something a config
  change or a quick patch fixes. Stage 2 (post-leak) is *not* the
  bottleneck — libc itself has thousands of gadgets once its base is
  known; verified separately with `ropper` against the loaded libc.
- **Physical hardware** (real UART/JTAG wiring, RF capture) can't be
  automated in software at all.

Optional environment for the network-facing adapters (all skip cleanly if unset):

    CYF_URL=http://target/path      python run.py --category web ...    # sqlmap/ffuf/jwt_attack(replay)/nuclei
    CYF_HOST=1.2.3.4 CYF_PORT=1337  python run.py --category pwn ...    # net_probe
    CYF_USERNAME=someuser           python run.py --category osint ...  # sherlock

## New from a "what would make this power through medium/hard challenges"
## pass — install real tools, don't just recommend them

The classifier's own `TOOLS` dict has recommended `nuclei` and `jwt_tool`
for web since the start of this project — the engine had zero code to
actually use either. Installed and wired for real, each verified against a
live target, not just imported:

- **`jwt_attack`** — a genuine crack-then-forge chain: finds a JWT in
  evidence, cracks its HMAC secret against jwt_tool's own curated weak-
  secret wordlist, then re-signs it with each common "become admin" claim
  override and replays it against `CYF_URL`. Verified end to end against a
  live Flask app with a weak HS256 secret (`tests/test_engine_smoke.py`).
- **`nuclei_scan`** — known-CVE/misconfiguration scanning. Measured
  honestly: even scoped to CTF-relevant tags, a real run took ~25-30s —
  that's the entire "medium" budget on one tool. Needs "hard" difficulty
  to reliably finish. It's also the wrong tool for "is there a bare
  `.env`/`.git` at the webroot" (that's `ffuf`'s job — path fuzzing, not
  nuclei's product/CVE-specific templates); said plainly in its own
  docstring so nobody expects nuclei to do that.
- **`sherlock_search`** — real, disclosed limitation: sherlock only tells
  you WHICH sites a username is registered on, not profile *content*, so
  it rarely produces a flag directly — it's recon evidence, same role
  `strings`/`file` play elsewhere. Also: its unscoped default sweep
  (400+ sites) simply didn't finish within any timeout this engine uses
  when actually measured (many sites are slow/rate-limit datacenter IPs);
  `config.SHERLOCK_SITES` trades sherlock's real strength (breadth) for
  finishing at all — a curated ~13-site list that runs in ~3-10s.

Installed via precompiled release binaries (nuclei — this box's Go 1.18
can't build it from source, a real environment constraint worth knowing
about) and `pip`/`git clone` (jwt_tool, sherlock was already present).
See the Setup section above for exact commands.

## pwn / Zeratool — requires a patch to actually work

`pip install zeratool` on its own is broken for real use, three separate ways:

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
3. **Format-string detector crash**: dereferences `end_state.globals`
   without checking `end_state` isn't `None` — crashes instead of
   reporting "not found" whenever exploration doesn't land a match.

All three are fixed in `patches/zeratool-fixes.patch` (verified: turns a
hard crash into a correct, automatic, zero-manual-intervention flag
capture on `challenges/pwn/ret2win`). Apply once after installing zeratool:

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
