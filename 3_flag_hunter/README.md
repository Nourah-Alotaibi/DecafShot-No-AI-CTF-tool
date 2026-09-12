# Decaf Flag Hunter

A deterministic CTF investigation engine. The ranker scores adapters using category weights, optional catalog popularity and current evidence. Tools write facts, signals and extracted files; the engine re-ranks until it finds a flag or exhausts its step budget.

- [Installation for Windows, Linux and macOS](../README.md#choose-a-setup)
- [Complete command and use-case help](../HELP.md)
- [Current validation and limitations](../docs/VALIDATION.md)
- [Historical development notes](../docs/HISTORICAL_ENGINE_NOTES.md) (environment-specific observations, not current guarantees)

From the repository root:

```bash
python 3_flag_hunter/run.py --doctor
python 3_flag_hunter/run.py --guide
python 3_flag_hunter/run.py --path ./challenge --category crypto --difficulty medium
python 3_flag_hunter/batch.py 3_flag_hunter/challenges --csv results.csv
```

## Code map

| File | Responsibility |
| --- | --- |
| `run.py` | Hunt CLI, input validation and help commands |
| `batch.py` | Corpus runner and CSV results |
| `cyf/config.py` | Flags, weights, step budgets, tool settings and targets |
| `cyf/catalog.py` | Reads selected popularity weights from the checked-in catalog |
| `cyf/evidence.py` | Facts, signals, text, extracted files and visited adapters |
| `cyf/ranker.py` | Explainable ranking |
| `cyf/tools.py` | 18 real/built-in adapters |
| `cyf/flag_miner.py` | Regex and bounded decoding ladder |
| `cyf/engine.py` | Rank/run/update loop |
| `cyf/help.py` | Offline capability and dependency inventory |

## Extending

Subclass `Tool`, implement `applicable()` and `run()`, register the instance in `REGISTRY`, and add weights in `BASE_WEIGHTS`. Add an entry to `CAPABILITIES` and update the help table. Test absent dependencies as well as positive fixtures.

Use `_all_files(ev)` to include extracted evidence. `_ingest_extracted()` registers a file and reopens file-consuming adapters, including the decoder and packet analyzer. Existing extraction chains are still limited: stegseek currently reads and deletes its payload instead of retaining it as a new file; some adapters only process the first compatible file. Timeouts are applied to individual subprocesses and do not enforce an overall run deadline.

## Zeratool patch

For Zeratool 2.2 in a compatible Linux environment, run from the repository root:

```bash
python -m pip install zeratool==2.2
bash patches/apply_zeratool_fixes.sh
```

Apply once. The patch addresses solver API changes, stack alignment and a None-result crash. It does not make arbitrary heap, format-string or gadget-poor binaries automatically solvable. See the historical notes for the original experiments and the validation report for what was actually rerun.
