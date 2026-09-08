"""
catalog.py — wires 2_tool_catalog's scraped, star-ranked GitHub data into the
ranker's weights. This closes the gap where BASE_WEIGHTS in config.py used to
be hand-typed with zero connection to the catalog the other project builds.

No generative model, no learning: it's a fixed normalization of a scraped
score (stars x recency), refreshed only when you rerun collect_tools.py.

How it's used: ranker.base_weight() blends the hand-authored weight in
config.BASE_WEIGHTS with this catalog-derived popularity signal, when we have
a real adapter for that catalog entry (see ALIASES below). Tools the catalog
doesn't know about (because they're not a top-8 GitHub result for that
category, e.g. stegseek, zeratool) just fall back to the hand-authored weight
untouched.
"""
import json
from pathlib import Path

CATALOG_PATH = Path(__file__).resolve().parents[2] / "2_tool_catalog" / "tools_catalog.json"

# engine tool name -> (catalog category, catalog entry name to match, case-insens.)
# Only list tools where we have a REAL adapter AND the catalog actually ranks
# that exact project — everything else stays purely hand-authored.
ALIASES = {
    "rsactftool":    ("crypto", "RsaCtfTool"),
    "binwalk_scan":  ("hardware", "binwalk"),
    "volatility":    ("forensics", "volatility3"),
    "web_sqlmap":    ("web", "sqlmap"),
    "web_ffuf":      ("web", "ffuf"),
}

_cache = None


def _load():
    global _cache
    if _cache is not None:
        return _cache
    if not CATALOG_PATH.exists():
        _cache = {}
        return _cache
    try:
        _cache = json.loads(CATALOG_PATH.read_text())
    except Exception:
        _cache = {}
    return _cache


def _normalized_scores(category: str) -> dict:
    """name.lower() -> score/max_score_in_category, for that category's tool list."""
    data = _load()
    tools = data.get(category, {}).get("tools", [])
    if not tools:
        return {}
    top = max(t["score"] for t in tools)
    if top <= 0:
        return {}
    return {t["name"].lower(): round(t["score"] / top, 3) for t in tools}


def catalog_weight(tool_name: str, category: str):
    """Return a 0..1 popularity weight for (tool_name, category) if the
    catalog ranks that tool for that category, else None (caller should fall
    back to the hand-authored weight)."""
    alias = ALIASES.get(tool_name)
    if not alias:
        return None
    cat, name = alias
    if cat != category:
        return None
    scores = _normalized_scores(cat)
    return scores.get(name.lower())
