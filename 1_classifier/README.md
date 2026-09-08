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
- Add training data in `_starter_dataset()` — scrape CTFtime / picoCTF
  writeups for a few hundred labeled challenges to make the ML stage pull weight.
- Add categories: extend `TOOLS`, `KEYWORD_SIGNALS`, `EXT_SIGNALS`.
- Tune escalation: `classify(..., ml_threshold=0.55)`.

## Files
- classifier.py     — the module (rule engine + ML + cascade)
- RELATED_WORK.md   — paper positioning + citations
- ctf_clf.joblib    — trained model (regenerate with --train)
