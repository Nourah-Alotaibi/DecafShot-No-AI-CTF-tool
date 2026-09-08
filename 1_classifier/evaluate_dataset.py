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

from classifier import _starter_dataset, _scraped_dataset


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


def main():
    hand = _starter_dataset()
    scraped = _scraped_dataset()
    seen, combined = set(), []
    for text, cat in hand + scraped:
        if text not in seen:
            seen.add(text)
            combined.append((text, cat))

    print(f"hand-written: {len(hand)} examples, {dict(Counter(c for _, c in hand))}")
    print(f"scraped:      {len(scraped)} examples, {dict(Counter(c for _, c in scraped))}")
    print(f"combined:     {len(combined)} examples (deduped)\n")

    for name, data in [("hand-written only", hand), ("hand-written + scraped", combined)]:
        accs, note = _cv_accuracy(data)
        if accs is None:
            print(f"{name:24} — {note}")
            continue
        mean = sum(accs) / len(accs)
        print(f"{name:24} — {note} CV accuracy: {mean:.3f} "
              f"(per-fold: {[round(a, 2) for a in accs]})")


if __name__ == "__main__":
    main()
