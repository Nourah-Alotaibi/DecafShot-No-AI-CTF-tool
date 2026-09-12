# Validation and engineering review

Date: 2026-09-12. Starting commit: `6bd76ea252127d8217d875b1913510c1cdf77241`.
Changes are on `docs/setup-help-validation`. These measurements cover this checkout
and the available environments, not every version of each upstream tool.

## Results

| Check | Result | Scope |
| --- | --- | --- |
| Existing engine suite, Ubuntu WSL/Python 3.10.12 | 32 passed, 0 skipped | Baseline before changes |
| Updated engine suite, Ubuntu WSL | 39 passed, 0 skipped | Existing integrations plus portability regressions |
| Updated engine suite, Windows/Python 3.13 | 26 passed, 13 skipped, 0 failed | Optional Linux tools absent; skips are not successes |
| Classifier/scraper unit suite, Windows | 13 passed | Rules, held-out phrasing and scraper parsing |
| Catalog unit suite, Windows | 3 passed | Filters, deduplication, default output path, consumer round-trip |
| Bundled medium corpus, WSL | 14/14 candidates found | Seven categories, small authored fixtures |
| Bundled medium corpus, native Windows | 6/14 candidates found | Core/fallback paths, no optional solver stack |
| Category routing smoke check | All nine categories passed | Same base64 fixture per category, not nine independent domain benchmarks |
| Adapter missing-dependency/target contracts | All 18 exercised | Mocked absence; does not establish external-tool compatibility |
| Classifier train and predict, WSL | Passed | Fresh in-memory training; tracked model unchanged |
| Dataset cross-validation, WSL | 0.500 / 0.590 / 0.686 | Seed / seed+GitHub / all data; five folds |
| GitHub collector live request | Returned `ffuf/ffuf` | One query; full refresh was not run |
| Scraper live dry-run | 89 labeled examples from one seed repository | Five categories; committed data unchanged |
| Optional playbook miner | One synthetic frontmatter fixture passed | External full playbook corpus not remade |
| macOS | Not run locally | Setup references reviewed; portable CI matrix added |

The new CI matrix covers Ubuntu, Windows and macOS with Python 3.10 and 3.13.
It runs portable tests and skips unavailable integrations; it is not a provisioned
full security-tool lab. CI execution is separate from the local results above.

Relevant WSL versions: scikit-learn 1.7.2, joblib 1.6.0, binwalk 2.3.3,
patched Zeratool 2.2, Volatility 3 version 2.28.0, nuclei 3.11.1.
The configured JWT and stegseek wordlists were available. The ffuf wordlist was
absent, so its integration test exercised the curl fallback.

## Category results

| Category | WSL corpus | Windows corpus | Additional evidence |
| --- | --- | --- | --- |
| crypto | 5/5 | 3/5 | Nested encodings, repeating XOR, RSA, archive-to-RSA chain |
| forensics | 3/3 | 1/3 | tshark stream reconstruction and HTTP-object extraction tests |
| hardware | 1/1 | 0/1 | Firmware with an embedded gzip payload; no physical hardware test |
| osint | 1/1 | 1/1 | Local metadata; separate live Sherlock account-presence test |
| pwn | 1/1 | 0/1 | Separate fresh-compiled ret2win integration passed |
| reverse | 1/1 | 1/1 | Direct radare2/objdump adapter check on encoded ELF data |
| stego | 2/2 | 0/2 | steghide password fixture and raw LSB fixture |
| web | No corpus fixture | No corpus fixture | Local SQLi and JWT integrations plus ffuf fallback |
| misc | No corpus fixture | No corpus fixture | Portable decoder/category-routing smoke check only |

See [WSL CSV](validation/linux-corpus.csv) and [Windows CSV](validation/windows-corpus.csv).
Some simple fixtures are solvable without the intended external tool: for example,
the metadata flag can be ingested by `file_id`. Native Windows recovering the
reverse fixture is not proof of a working Windows ELF reverse-engineering toolchain.
The pwn corpus passed in an already provisioned WSL environment; its binary may
depend on external runtime/files. The fresh-compiled integration is stronger evidence.

## Adapter-by-adapter evidence

| Adapter | Positive evidence / limitation |
| --- | --- |
| file_id | Direct metadata fixture produced flag-bearing text |
| strings_scan | Direct printable-text extraction produced the expected candidate |
| decode_ladder | Direct ROT13 plus nested base64/32/gzip/zlib, hex, URL, rotations and XOR regressions |
| binwalk_scan | Direct firmware extraction and recursive extraction integration passed |
| exif_scan | Direct metadata read produced expected flag; not inferred from a corpus shortcut |
| rsactftool | Direct weak-RSA decryption and delayed-key extraction integration passed |
| zeratool_pwn | Direct bundled binary and fresh-compiled ret2win integration passed |
| stegseek | Direct steghide fixture yielded its expected payload |
| zsteg_scan | Direct LSB fixture and generated-image integration passed |
| reverse_analyze | Direct radare2/objdump section extraction, followed by decoding, recovered expected flag |
| pcap_analyze | Direct stream output plus decoding recovered expected flag; HTTP export chain also passed |
| net_probe | Local TCP listener integration passed |
| web_sqlmap | Local SQLite-backed HTTP lab integration passed |
| web_ffuf | Local exposed-file fallback passed; real wordlist branch remains unvalidated for flag recovery |
| jwt_attack | Local weak-HMAC-secret forge/Bearer-replay integration passed |
| sherlock_search | Live account-presence integration passed; this is recon, not a flag solve |
| nuclei_scan | Installed, and no-target behavior passed; no positive vulnerability-detection fixture validated |
| volatility | Eight plugins invoked on an invalid synthetic image without adapter crash; no valid memory-image recovery validated |

Therefore **not all features are proven to work end to end**. In particular, nuclei
positive detection and real memory forensics remain open. Optional tools have much
larger feature sets than these adapters expose; testing DecafShot is not testing
every upstream feature. Direct adapter evidence is in
[adapter-results.json](validation/adapter-results.json); the reproducible audit script
is [adapter_audit.py](validation/adapter_audit.py).

## Changes made

- Added separate WSL, native Windows, Linux and macOS setup paths with isolated Python environments.
- Added a complete help page plus `--guide`, `--list-tools` and non-executing `--doctor`.
- Validated category names and missing challenge paths at the CLI boundary.
- Fixed catalog regeneration: default output now matches the engine's input directory;
  added `--outdir` for previews, positive-count validation and UTF-8 output.
- Fixed newly extracted evidence: binwalk/ExifTool now inspect extracted files;
  new files reopen the decode ladder and packet analyzer.
- Prevented empty RSA ciphertext from raising an IndexError.
- Corrected the optional RSA integration to skip when its dependency is missing.
- Added regression coverage for the above and a portable CI matrix.
- Moved environment-specific historical claims out of the active engine setup guide.

## Opinion and priorities

This is a useful, understandable CTF triage assistant with real integrations.
Evidence-based re-ranking, readable traces and reproducible fixtures are its strengths.
The next gains should come from reliable execution and broader evaluation rather
than a larger tool-name catalog. The current evidence does not establish general
medium/hard challenge solving or a research novelty claim.

1. **Make execution results trustworthy.** `_sh()` merges stdout/stderr and loses
   return-code semantics. A timeout or tool usage error can look like an ordinary
   no-result run, and nuclei counts nonempty output lines as findings. Return
   structured status, exit code, timing, stdout/stderr and candidate provenance.
   Add an overall monotonic deadline, subprocess-tree cancellation, and bounded
   input/output/decompression sizes. Several adapter loops can exceed the stated
   per-tool budget; the decoder's inflate path is not output-size bounded.

2. **Complete extraction workflows.** Retain stegseek's extracted payload as a file;
   process all compatible files rather than only the first; deduplicate artifacts
   by content to avoid repeated extraction into fresh temporary directories.
   Reconsider tools by relevant evidence changes instead of clearing every file
   tool. Clean up per-run temporary directories after the run, with an option to
   retain evidence. Native fallback reads should preserve ciphertext bytes and
   identify file types without depending solely on the `file` executable.

3. **Build a trustworthy benchmark.** Add expected flags and negative fixtures,
   category-balanced real challenges, web/Volatility/nuclei positive fixtures, and
   harder multi-stage tasks. Report missing dependencies separately from failures.
   Compare fixed-order, hand-weight-only and catalog-blended rankers under equal
   budgets. Current `batch.py` accepts any matching flag regex and reports the last
   tool as solver even when earlier tools supplied the essential evidence.

4. **Improve the classifier evaluation.** Reproduced 68.6% is ML text-classification
   cross-validation accuracy, not challenge solve rate or full cascade accuracy.
   Split by event/source to reduce related-writeup leakage, report per-category
   precision/recall and confidence calibration, and gather more hardware/stego data.
   GitHub stars are popularity, not measured expected solve yield. Version the
   training data/model and record dependency versions when producing artifacts.

5. **Improve the player workflow.** Add a unified classify-then-hunt entry point,
   configurable flag formats/wordlists/targets, a single-tool mode, JSON evidence
   export and resume support. Fetch relevant ffuf discovery bodies and preserve
   decoded intermediate content for follow-up steps. Add a Linux integration CI
   job with pinned solver versions, wordlists and deterministic local services.
   Choose an explicit repository license so reuse terms are clear.

These are recommendations, not claims that those larger changes were implemented.
