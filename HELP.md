# DecafShot command and CTF play guide

Run from the repository root. Activate `.venv` on Linux/macOS; on native Windows replace `python` with `.\.venv\Scripts\python.exe`. [Installation](README.md#choose-a-setup).

## Discover commands

```bash
python 3_flag_hunter/run.py --help
python 3_flag_hunter/run.py --guide
python 3_flag_hunter/run.py --list-tools
python 3_flag_hunter/run.py --doctor
```

`--guide` displays this page offline. `--doctor` checks executables, wordlists and target configuration without running tools or contacting targets. It does not certify versions, patches, symbols or templates.

## Playing a challenge

1. Put one challenge's files in their own folder. Keep reports and unrelated flags outside it.
2. Classify the supplied description/files. Read confidence and signals; `REVIEW` asks for human judgment. `SAFE` is an internal classifier label, not competition approval.
3. Choose a category and run the hunter. Classification does not automatically launch it.
4. Read the ranking, facts and skipped-tool messages. Install missing tools or inspect evidence manually. Categories guide ranking, not a strict tool allowlist.
5. Confirm a candidate flag against the challenge. No result means only that this run did not solve it.

```bash
python 1_classifier/classifier.py --text "RSA public key and ciphertext"
python 1_classifier/classifier.py --path ./challenge --text "challenge description"
python 3_flag_hunter/run.py --path ./challenge --category crypto --difficulty medium
python 3_flag_hunter/run.py --path ./challenge --category crypto --difficulty hard --quiet
```

Hunter options: `--path` file/directory (required for hunting), `--category` (default `misc`), `--difficulty easy|medium|hard` (default medium), `--quiet`, and the four information commands above. No CLI option currently selects a single adapter, auto-classifies, changes timeouts or exports JSON.

## Examples for all nine categories

```bash
# crypto: nested encodings or weak RSA
python 3_flag_hunter/run.py --path 3_flag_hunter/challenges/crypto/b64_gzip --category crypto
python 3_flag_hunter/run.py --path 3_flag_hunter/challenges/crypto/rsa_weak --category crypto
# forensics: packet streams and embedded archives
python 3_flag_hunter/run.py --path 3_flag_hunter/challenges/forensics/pcap_http_object --category forensics
# stego: LSB payload (zsteg)
python 3_flag_hunter/run.py --path 3_flag_hunter/challenges/stego/lsb_no_pass --category stego
# reverse: encoded ELF data
python 3_flag_hunter/run.py --path 3_flag_hunter/challenges/reverse/xor_in_data --category reverse
# pwn: compatible Linux lab, patched Zeratool
python 3_flag_hunter/run.py --path 3_flag_hunter/challenges/pwn/ret2win --category pwn --difficulty hard
# osint: local photo metadata
python 3_flag_hunter/run.py --path 3_flag_hunter/challenges/osint/exif_leak --category osint
# hardware: offline firmware analysis
python 3_flag_hunter/run.py --path 3_flag_hunter/challenges/hardware/firmware_dump --category hardware
# misc: unknown local challenge
python 3_flag_hunter/run.py --path ./challenge --category misc
# web: first create challenge.txt with lab notes and set CYF_URL below
python 3_flag_hunter/run.py --path ./challenge.txt --category web --difficulty hard
```

The committed pwn binary can depend on external files/runtime state. Its integration test compiles a fresh ret2win and creates the flag file, making that test more portable than the binary fixture.

## Targets in Bash and PowerShell

Use competition-authorized targets. Localhost examples assume your own lab service is already running. Create `challenge.txt` with challenge notes or the JWT supplied by the lab.

```bash
CYF_URL='http://127.0.0.1:8000/user?id=1' python 3_flag_hunter/run.py --path challenge.txt --category web --difficulty hard
CYF_HOST=127.0.0.1 CYF_PORT=1337 python 3_flag_hunter/run.py --path challenge.txt --category pwn
CYF_USERNAME=ctf_example_username python 3_flag_hunter/run.py --path challenge.txt --category osint
```

```powershell
$env:CYF_URL = 'http://127.0.0.1:8000/user?id=1'
.\.venv\Scripts\python.exe 3_flag_hunter\run.py --path challenge.txt --category web --difficulty hard
Remove-Item Env:CYF_URL
$env:CYF_HOST = '127.0.0.1'
$env:CYF_PORT = '1337'
.\.venv\Scripts\python.exe 3_flag_hunter\run.py --path challenge.txt --category pwn
Remove-Item Env:CYF_HOST, Env:CYF_PORT
```

Set `$env:CYF_USERNAME` similarly for Sherlock, then clear it. Settings persist in a shell until removed. `CYF_PORT` must be an integer. JWT replay uses Bearer tokens, not arbitrary cookie flows. Sherlock returns account locations, usually not flags.

## All 18 adapters

| Adapter | Main use | Dependency / input |
| --- | --- | --- |
| `file_id` | File-type signals | file, basic fallback |
| `strings_scan` | Printable strings | strings, Python fallback |
| `decode_ladder` | base64/32, hex, ROT13/47, Atbash, URL, Morse, gzip/zlib, XOR | Built in; bounded search |
| `binwalk_scan` | Embedded archive/firmware extraction | binwalk and extractors |
| `exif_scan` | Metadata | exiftool |
| `rsactftool` | Weak RSA | RsaCtfTool, key, optional ciphertext |
| `zeratool_pwn` | Automatic ELF exploitation | Patched Zeratool, Linux runtime |
| `stegseek` | Steghide password search | stegseek, carrier, wordlist |
| `zsteg_scan` | PNG/BMP LSB analysis | zsteg |
| `volatility` | Memory evidence | Volatility 3, image, symbols |
| `pcap_analyze` | Stream reconstruction/HTTP exports | tshark, capture |
| `reverse_analyze` | ELF functions/imports/data | radare2 and/or GNU objdump |
| `web_sqlmap` | SQL injection | sqlmap, CYF_URL |
| `web_ffuf` | Web paths | ffuf, wordlist; curl for fallback |
| `net_probe` | TCP banner and newline probe | Built in, CYF_HOST/CYF_PORT |
| `jwt_attack` | Weak-secret JWT forge/replay | jwt_tool, JWT text, secret wordlist; optional CYF_URL |
| `nuclei_scan` | Template-based findings | nuclei, templates, CYF_URL |
| `sherlock_search` | Username presence | sherlock, internet, CYF_USERNAME |

Morse produces lowercase words and has no braces; Morse alone generally cannot match the default flag regex. Hardware means firmware/file analysis, not physical UART/JTAG control. Reverse analysis is not a full decompiler or arbitrary program solver.

## Training, catalog and evaluation

```bash
python 1_classifier/classifier.py --train
python 1_classifier/evaluate_dataset.py
python 1_classifier/scrape_ctf_writeups.py --help
python 1_classifier/scrape_ctf_writeups.py --max-repos 1 --dry-run
python 1_classifier/mine_m0x_playbooks.py --help
python 1_classifier/mine_m0x_playbooks.py /path/to/playbooks --max-per-category 400 --dry-run
python 2_tool_catalog/collect_tools.py --help
python 2_tool_catalog/collect_tools.py 8
python 2_tool_catalog/collect_tools.py 8 --outdir ./catalog-preview
python 3_flag_hunter/batch.py --help
python 3_flag_hunter/batch.py 3_flag_hunter/challenges --difficulty medium --csv results.csv
```

`--train` replaces `ctf_clf.joblib`; retrain if incompatible with your installed sklearn version. Scraper dry-run still uses the network but avoids writing. The miner requires an optional external playbook directory and only reads data; it does not invoke an AI agent. Cross-validation may take time.

Collector count defaults to 8. Default output replaces `2_tool_catalog/tools_catalog.json`, `.md` and `TOOLS_snippet.py`, where the engine reads. `--outdir` creates a preview. `GITHUB_TOKEN` optionally authenticates GitHub requests. The classifier's tool dictionary remains static. Batch expects `<category>/<challenge>/files`; unknown folders default to misc. Batch exit status does not require every case to solve: inspect the CSV.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| No flag within budget | Inspect facts, flag format, dependencies and category; increase effort or analyze manually. |
| Tool skipped | Run doctor in the same shell/interpreter; add its executable to PATH. |
| Unix tool absent in native Windows | Run both Python and tool inside WSL. |
| Model compatibility error | Retrain locally with your installed sklearn version. |
| Extractor errors | Check binwalk interface/version and archive utilities. |
| ffuf finds paths but no flag | Its wordlist branch reports findings but does not fetch discovered page bodies; inspect paths manually. |
| Nuclei/Volatility finds nothing | Check templates/symbols and raw output. No finding is not proof of absence. |
| Test skipped | Install dependencies before claiming that integration passed. |

See [test results and review](docs/VALIDATION.md) for remaining gaps and priorities.
