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

## Files
- classifier.py           — the module (rule engine + ML + cascade)
- scrape_ctf_writeups.py  — pulls real labeled data from public write-up repos
- evaluate_dataset.py     — before/after cross-validation accuracy
- scraped_dataset.json    — scraper output, committed like tools_catalog.json
                            (regenerate with the scraper, don't hand-edit)
- RELATED_WORK.md         — paper positioning + citations
- ctf_clf.joblib          — trained model (regenerate with --train)
- tests/test_classifier.py — rule-engine regression + held-out-phrasing tests
