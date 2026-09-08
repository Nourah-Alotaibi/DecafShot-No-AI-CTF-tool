"""
ranker.py — the deterministic action ranker (the "brain").

score(tool) = base_weight[category]  x  applicability(evidence)

Both factors are plain numbers. Because applicability reads the evidence
blackboard, the ranking CHANGES after every tool runs — that's the adaptive
reranking, achieved with zero learning. Every score is explainable.

base_weight itself is now a blend of two plain numbers when the catalog has
data for that tool: the hand-authored weight in config.BASE_WEIGHTS, and a
popularity weight normalized from 2_tool_catalog's scraped GitHub scores
(catalog.py). Tools the catalog doesn't rank just use the hand-authored
weight untouched — still fully explainable, still no learning.
"""
from .config import BASE_WEIGHTS
from .evidence import Evidence
from .catalog import catalog_weight


def base_weight(tool_name: str, category: str) -> tuple:
    """Return (weight, explanation) for a tool in a category."""
    row = BASE_WEIGHTS.get(tool_name, {})
    hand = row.get(category, row.get("*", 0.1))
    cat_w = catalog_weight(tool_name, category)
    if cat_w is None:
        return hand, f"hand {hand:.2f}"
    blended = round((hand + cat_w) / 2, 3)
    return blended, f"hand {hand:.2f} + catalog {cat_w:.2f} = {blended:.2f}"


def score_tools(tools, ev: Evidence):
    """Return [(tool, score, explanation), ...] sorted high to low."""
    ranked = []
    for t in tools:
        appl = t.applicable(ev)
        if appl <= 0:
            continue                          # not applicable / already ran
        bw, bw_why = base_weight(t.name, ev.category)
        s = round(bw * appl, 3)
        why = f"base[{bw_why}](cat={ev.category}) x fit {appl:.2f} = {s:.2f}"
        ranked.append((t, s, why))
    ranked.sort(key=lambda x: x[1], reverse=True)
    return ranked
