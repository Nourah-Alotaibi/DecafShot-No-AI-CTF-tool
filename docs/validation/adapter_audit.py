"""Run from any directory with the provisioned Linux tool environment.

Exercises real local fixture adapters, an invalid memory image, one GitHub query,
a synthetic playbook and in-memory ML training. Writes adapter-results.json here.
Read printed candidates; this records observations, not a full assertion suite.
"""
import sys, json, tempfile, time
from pathlib import Path
root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / "3_flag_hunter"))
from cyf import config
from cyf.evidence import Evidence
from cyf.tools import REGISTRY, FileId
from cyf.flag_miner import decode_ladder, find_flag
rows = []
fixtures = {
    "file_id": ("osint", "osint/exif_leak"),
    "strings_scan": ("osint", "osint/exif_leak"),
    "decode_ladder": ("crypto", "crypto/rot13"),
    "binwalk_scan": ("hardware", "hardware/firmware_dump"),
    "exif_scan": ("osint", "osint/exif_leak"),
    "rsactftool": ("crypto", "crypto/rsa_weak"),
    "zeratool_pwn": ("pwn", "pwn/ret2win"),
    "stegseek": ("stego", "stego/steghide_weak"),
    "reverse_analyze": ("reverse", "reverse/xor_in_data"),
    "zsteg_scan": ("stego", "stego/lsb_no_pass"),
    "pcap_analyze": ("forensics", "forensics/pcap_creds"),
}
for tool in REGISTRY:
    if tool.name not in fixtures:
        continue
    category, relative = fixtures[tool.name]
    ev = Evidence(category=category, challenge_path=str(root / "3_flag_hunter/challenges" / relative))
    if tool.name == "decode_ladder":
        FileId().run(ev, 10)
    start = time.monotonic()
    tool.run(ev, 60)
    candidates = [ev.flag] if ev.flag else []
    for blob in ev.text_blobs:
        f = find_flag(blob)
        if f:
            candidates.append(f)
    if not candidates and tool.name in ("reverse_analyze", "pcap_analyze"):
        for blob in ev.text_blobs:
            f, _ = decode_ladder(blob)
            if f:
                candidates.append(f)
    row = dict(adapter=tool.name, seconds=round(time.monotonic()-start, 2), candidates=list(set(candidates)), facts=ev.facts)
    rows.append(row)
    print(json.dumps(row), flush=True)

# Volatility can be invoked, but there is no valid memory fixture in the repo.
with tempfile.TemporaryDirectory() as d:
    p = Path(d) / "invalid.raw"
    p.write_bytes(b"\x00" * 4096)
    ev = Evidence(category="forensics", challenge_path=str(p))
    next(t for t in REGISTRY if t.name == "volatility").run(ev, 4)
    rows.append(dict(adapter="volatility", result="invalid-image invocation only; no positive fixture", facts=ev.facts, sample=ev.text_blobs[:1]))

Path(__file__).with_name("adapter-results.json").write_text(json.dumps(rows, indent=2))

sys.path.insert(0, str(root / "2_tool_catalog"))
import collect_tools
items, remaining = collect_tools.gh_search("repo:ffuf/ffuf", per_page=1)
print("LIVE_CATALOG", json.dumps({"results": [x["full_name"] for x in items], "remaining": remaining}), flush=True)

sys.path.insert(0, str(root / "1_classifier"))
import classifier, mine_m0x_playbooks
with tempfile.TemporaryDirectory() as d:
    p = Path(d) / "sample.md"
    p.write_text("---\ntitle: Weak RSA public exponent challenge\ncategory: crypto\ntechniques: [rsa, factorization]\nevent: Local test\n---\n")
    data, counts = mine_m0x_playbooks.mine(Path(d), 1)
    assert counts == {"crypto": 1}, counts
    print("MINER_FIXTURE", json.dumps(data), flush=True)
pipe = classifier.train(save=False)
result = classifier.ml_scan("recover a private key from RSA modulus", pipe=pipe)
print("ML_TRAIN_PREDICT", result.to_json(), flush=True)
