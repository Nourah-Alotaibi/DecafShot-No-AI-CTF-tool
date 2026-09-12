# CTF Category & Tool Classifier

Rule + traditional-ML cascade for the Control Room pre-scan layer. Give it a challenge,
get back the category, confidence, recommended tools, and which policy
tier resolved it.

## Install
    pip install scikit-learn joblib

## Use
    python classifier.py --train                      # build the ML model
    python classifier.py --text "RSA public key, small e, recover the flag"
    python classifier.py --path ./challenge_dir       # inspects files with `file`
    python classifier.py --path ./chal --text "..."   # both signals

Or import it:
    from classifier import classify
    r = classify(text="sql injection in the login form")
    print(r.category, r.confidence, r.tools, r.tier)

## How it works (the cascade)
1. RULE ENGINE     — file extensions + keyword signatures. Deterministic,
                     explainable. SAFE tier. Resolves most challenges.
2. ML CLASSIFIER   — TF-IDF + LogisticRegression on the text. Offline,
                     traditional ML (no generative models). SAFE tier.
                     Breaks ties the rules can't.
3. (Manual review) — only if ML confidence < threshold. Flagged REVIEW tier
                     for a human to confirm; that step lives elsewhere.

This maps 1:1 onto the SAFE / REVIEW / BLOCKED policy ladder: stages 1-2 are
competition-legal on their own, which is the answer to "no generative model" events.

## Extending
- Add categories: extend `TOOLS`, `KEYWORD_SIGNALS`, `EXT_SIGNALS`.
- Tune escalation: `classify(..., ml_threshold=0.55)`.

## Growing the ML training set with real data

`_starter_dataset()` is a small hand-written seed. `scrape_ctf_writeups.py`
pulls real, labeled examples from public CTF write-up repos instead of more
hand-typed sentences — the label comes from the `# name (category, Npts, N
solved)` title line convention most write-ups share (copied from
ctftime.org's own listing format), not from directory names (tried that
first; real aggregator repos organize by event+challenge-name, not
category, so there was no signal there).

    python3 scrape_ctf_writeups.py            # writes scraped_dataset.json
    python3 classifier.py --train             # now trains on hand-written + scraped, deduped
    python3 evaluate_dataset.py               # honest before/after CV accuracy

`train()` uses `scraped_dataset.json` automatically when present (falls
back to the hand-written set alone if it's missing — nothing breaks if you
skip the scrape). `evaluate_dataset.py` reports stratified k-fold CV
accuracy for both, so any claimed improvement is a measured number, not an
assumption — see RELATED_WORK.md's "honest measurement" note for why that
matters here specifically.

### A second, much bigger real source: m0x-skills-ctfs' playbook library

If you have the `m0x-skills-ctfs` skill installed (a separate, optional
LLM-agent prompt library — NOT related to or required by this project; see
the note below), its `playbooks/` directory has ~10,800 real CTF writeup
summaries with clean YAML frontmatter (`category`, `techniques`, `event`).
`mine_m0x_playbooks.py` extracts that as plain data — nothing about that
skill's own agent/prompt behavior is invoked, just its playbook files read
and parsed:

    python3 mine_m0x_playbooks.py                # writes scraped_dataset_m0x.json
    python3 classifier.py --train                # now trains on all three sources
    python3 evaluate_dataset.py

Measured (stratified 5-fold CV):

| Training data | Examples | Accuracy |
|---|---|---|
| hand-written only | 80 | 0.500 |
| + github-scraped | 222 | 0.590 |
| + m0x-mined | 2,621 | **0.686** |

`hardware` and `stego` stay thin even with m0x mined in (4 and 77
examples) — m0x doesn't have dedicated top-level folders for either (both
get routed out of its `misc` bucket by technique tag: `steg`/`lsb` →
stego, `firmware`/`jtag`/`uart`/... → hardware), and real CTFs simply
produce far fewer of those challenges to begin with. That's a genuine,
disclosed ceiling, not a mining bug.

**Why m0x itself isn't wired in as a tool**: it's a *prompt library* meant
to be loaded into an LLM agent's context so the agent reasons through
challenges live (`SKILL.md`: *"You are M0x, an autonomous CTF solver"*).
That's the exact thing this project's `RELATED_WORK.md` positions itself
against — Decaf's whole claim is multi-category + adaptive + no generative
model. Using m0x live would just replace the deterministic engine with an
LLM reasoning session. Its playbook *data*, mined as plain (text, category)
pairs the same way scrape_ctf_writeups.py mines GitHub, is a different
thing entirely and stays on-thesis.

## Files
- classifier.py             — the module (rule engine + ML + cascade)
- scrape_ctf_writeups.py    — pulls real labeled data from public write-up repos
- mine_m0x_playbooks.py     — extracts labeled data from the (optional) m0x-skills-ctfs playbook library
- evaluate_dataset.py       — before/after cross-validation accuracy across all sources
- scraped_dataset.json      — GitHub-scraper output, committed like tools_catalog.json
- scraped_dataset_m0x.json  — m0x-miner output, committed (regenerate with the miner, don't hand-edit either)
- RELATED_WORK.md           — paper positioning + citations
- ctf_clf.joblib            — trained model (regenerate with --train)
- tests/test_classifier.py — rule-engine regression + held-out-phrasing tests
