#!/usr/bin/env python3
"""
evaluate_dataset.py — honest before/after accuracy measurement for the ML
stage, following RELATED_WORK.md's own convention: report the real
cross-validation number, don't just claim an improvement.

Runs stratified k-fold CV twice: hand-written seed set alone, then
hand-written + scraped combined. Prints both so a reader can see exactly
what the scraped data bought (or didn't).

Usage:
    python3 evaluate_dataset.py
"""
from collections import Counter

from classifier import _starter_dataset, _scraped_dataset, _scraped_m0x_dataset


def _cv_accuracy(data, folds=5):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import StratifiedKFold
    from sklearn.pipeline import Pipeline
    import numpy as np

    X = [t for t, _ in data]
    y = [c for _, c in data]
    counts = Counter(y)
    min_class = min(counts.values())
    k = min(folds, min_class)
    if k < 2:
        return None, f"can't cross-validate: smallest class has only {min_class} example(s)"

    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=0)
    accs = []
    Xa, ya = np.array(X, dtype=object), np.array(y, dtype=object)
    for train_idx, test_idx in skf.split(Xa, ya):
        pipe = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
            ("clf", LogisticRegression(max_iter=1000, C=4.0)),
        ])
        pipe.fit(Xa[train_idx], ya[train_idx])
        preds = pipe.predict(Xa[test_idx])
        accs.append(float(np.mean(preds == ya[test_idx])))
    return accs, f"{k}-fold"


def _dedupe(pairs):
    seen, out = set(), []
    for text, cat in pairs:
        if text not in seen:
            seen.add(text)
            out.append((text, cat))
    return out


def main():
    hand = _starter_dataset()
    github_scraped = _scraped_dataset()
    m0x_scraped = _scraped_m0x_dataset()

    hand_plus_github = _dedupe(hand + github_scraped)
    everything = _dedupe(hand + github_scraped + m0x_scraped)

    print(f"hand-written:        {len(hand)} examples, {dict(Counter(c for _, c in hand))}")
    print(f"github-scraped:      {len(github_scraped)} examples, "
          f"{dict(Counter(c for _, c in github_scraped))}")
    print(f"m0x-mined:           {len(m0x_scraped)} examples, "
          f"{dict(Counter(c for _, c in m0x_scraped))}")
    print(f"hand + github:       {len(hand_plus_github)} (deduped)")
    print(f"hand + github + m0x: {len(everything)} (deduped)\n")

    for name, data in [("hand-written only", hand),
                        ("hand + github-scraped", hand_plus_github),
                        ("hand + github + m0x", everything)]:
        accs, note = _cv_accuracy(data)
        if accs is None:
            print(f"{name:24} — {note}")
            continue
        mean = sum(accs) / len(accs)
        print(f"{name:24} — {note} CV accuracy: {mean:.3f} "
              f"(per-fold: {[round(a, 2) for a in accs]})")


if __name__ == "__main__":
    main()
