![DecafShot](decaf.png)

# DecafShot

**Decaffeinated. De-AI'd CTF kit.** A deterministic assistant for capture-the-flag challenges: classify a challenge, collect evidence, rank installed tools, and search for a flag. No generative model is required.

**[Command and use-case help](HELP.md)** · **[Test results and review](docs/VALIDATION.md)** · [Engine details](3_flag_hunter/README.md)

## Components

| Component | Purpose |
| --- | --- |
| `1_classifier/` | Rules plus optional TF-IDF/logistic regression suggest categories and tools. |
| `2_tool_catalog/` | Refreshes GitHub tool recommendations; selected entries influence engine weights. |
| `3_flag_hunter/` | Runs 18 adapters with evidence-based re-ranking and bounded decoding. |

Categories: `web`, `crypto`, `reverse`, `pwn`, `forensics`, `stego`, `osint`, `hardware`, `misc`. Classification and hunting are separate commands: pass the suggested category to the hunter. Catalog recommendations do not automatically install tools or create adapters.

**No generative AI or LLM runtime:** solving uses deterministic tools and rules;
the optional classifier is TF-IDF plus logistic regression, not a language model.
No model API key is needed. Catalog collection filters out explicitly LLM/generative-AI
tools, and three such recommendations were removed from the saved catalog.
Optional playbook datasets are read as text data, not executed as agent prompts.

Local file solving can run offline once dependencies/resources are installed. Catalog refresh, scraping, remote targets and username searches require network access. Use active tools against your own labs or competition-authorized targets and follow the event's automation rules.

## Choose a setup

Python **3.10+** is required for the standard-library core. ML classification additionally needs `scikit-learn` and `joblib`. Optional solvers have their own Python, OS and architecture requirements.

| Environment | Coverage |
| --- | --- |
| Windows + Ubuntu WSL | Recommended Windows route for Linux security tools and ELF challenges. |
| Linux (Ubuntu/Debian/Kali) | Broadest adapter coverage with optional dependencies installed. |
| Native Windows | Core decoder, basic file scanning, rules and ML; Unix tools need compatible installations. |
| macOS (Intel/Apple Silicon) | Core, classifier and compatible CLI tools; use a Linux VM for Linux ELF exploitation. |

### Windows: Ubuntu WSL

In administrator PowerShell, restart if prompted, then finish Ubuntu's first-run setup:

```powershell
wsl --install -d Ubuntu
wsl -d Ubuntu
```

Continue with the Linux commands **inside Ubuntu**. Prefer a clone in the Linux filesystem for ELF execution. [Microsoft WSL installation guide](https://learn.microsoft.com/en-us/windows/wsl/install).

### Linux: Ubuntu, Debian or Kali

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip file binutils
git clone https://github.com/Nourah-Alotaibi/DecafShot-No-AI-CTF-tool.git
cd DecafShot-No-AI-CTF-tool
python3 -m venv .venv
source .venv/bin/activate
python -m pip install scikit-learn joblib
python 3_flag_hunter/run.py --doctor
```

The pip step is optional for the core hunter. Use a virtual environment instead of modifying distribution-managed Python. Other distributions can use their package manager equivalents for Python, Git, `file` and GNU binutils.

### Native Windows: PowerShell

Install Python 3.10+ and Git, then open a fresh PowerShell:

```powershell
git clone https://github.com/Nourah-Alotaibi/DecafShot-No-AI-CTF-tool.git
cd DecafShot-No-AI-CTF-tool
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install scikit-learn joblib
.\.venv\Scripts\python.exe 3_flag_hunter\run.py --doctor
.\.venv\Scripts\python.exe 3_flag_hunter\run.py --path 3_flag_hunter\challenges\crypto\rot13 --category crypto
```

Calling the virtual-environment executable directly needs no activation-policy change. For later `python ...` examples substitute `.\.venv\Scripts\python.exe`. Windows executables must be on PATH; WSL tools are not visible to native Python. Prefer WSL for Zeratool and bundled Linux binaries.

### macOS: Terminal

With [Homebrew](https://brew.sh/) installed:

```bash
brew install python git binutils exiftool wireshark
git clone https://github.com/Nourah-Alotaibi/DecafShot-No-AI-CTF-tool.git
cd DecafShot-No-AI-CTF-tool
python3 -m venv .venv
source .venv/bin/activate
python -m pip install scikit-learn joblib
export PATH="$(brew --prefix binutils)/bin:$PATH"
python 3_flag_hunter/run.py --doctor
```

Check that `objdump` is GNU binutils when analyzing ELF sections. `brew --prefix` handles Intel/Apple Silicon prefix differences. See the [binutils](https://formulae.brew.sh/formula/binutils), [ExifTool](https://formulae.brew.sh/formula/exiftool) and [Wireshark CLI](https://formulae.brew.sh/formula/wireshark) formulas. macOS commands were documentation-reviewed, not executed here. An ARM Linux VM cannot natively run bundled x86-64 ELF fixtures; choose a compatible lab or rebuild appropriate fixtures.

## Optional tool packs

Install what the challenge needs, then run `--doctor`. PATH discovery does not certify solver compatibility.

```bash
# Ubuntu/Debian: extraction, metadata and packet analysis
sudo apt install -y binwalk libimage-exiftool-perl tshark unzip p7zip-full
# In the activated Python environment
python -m pip install volatility3 sqlmap sherlock-project
# Optional integration-test fixture dependencies
python -m pip install scapy pillow pyjwt
```

| Tool | Installation / resources |
| --- | --- |
| RsaCtfTool | Clone [upstream](https://github.com/RsaCtfTool/RsaCtfTool) into a separate tools directory, then `python -m pip install -e /path/to/RsaCtfTool`. A clone alone does not add the command to PATH. Some attacks need SageMath. |
| Zeratool | In compatible Linux: `python -m pip install zeratool==2.2`, then from this repo root `bash patches/apply_zeratool_fixes.sh`. Patch targets 2.2; apply once. |
| stegseek | Follow [upstream](https://github.com/RickdeJager/stegseek) for your distro. Needs a plaintext wordlist; configure `STEGSEEK_WORDLIST` in `cyf/config.py`. |
| zsteg | With Ruby installed: `gem install zsteg`; add the gem executable directory to PATH. [Upstream](https://github.com/zed-0xff/zsteg). |
| radare2 | Install an [upstream release](https://github.com/radareorg/radare2). GNU objdump provides partial fallback. |
| ffuf | Install a [release](https://github.com/ffuf/ffuf) or `go install github.com/ffuf/ffuf/v2@latest` with supported Go; put Go's bin directory on PATH. Needs curl for the no-wordlist fallback. |
| jwt_tool | Clone [upstream](https://github.com/ticarpi/jwt_tool), install its requirements, expose `jwt_tool.py` on PATH. Set `JWT_WORDLIST` in config to its `jwt-common.txt`. Keep script and supporting resources together. |
| nuclei | Install a matching [release](https://github.com/projectdiscovery/nuclei), then run `nuclei -update-templates` before offline lab use. |

Accepted executable names/paths live in `3_flag_hunter/cyf/config.py` (`TOOL_BIN`). Wordlists, memory symbols and scanner templates are separate resources. The binwalk adapter uses the v2-style `-e -M -C` interface; package versions can differ.

## First challenge

From the repository root:

```bash
python 3_flag_hunter/run.py --help
python 3_flag_hunter/run.py --guide
python 3_flag_hunter/run.py --list-tools
python 3_flag_hunter/run.py --doctor
python 1_classifier/classifier.py --text "RSA public key, recover the flag"
python 3_flag_hunter/run.py --path 3_flag_hunter/challenges/crypto/rot13 --category crypto --difficulty medium
```

The ROT13 fixture returns `FLAG{c4esar_sh1ft_by_13}`. `--quiet` prints only the flag on success. Exit codes: 0 = success/information, 1 = no flag, 2 = invalid arguments. Difficulty controls effort: easy/medium/hard = 4/8/14 steps and 15/30/60-second subprocess timeouts. Adapters may invoke several subprocesses, so these are **not total wall-clock limits**.

Default prefixes: `CYF`, `FLAG`, `CTF`. Edit `FLAG_REGEX` in config for other formats; XOR cribs are separately defined in `flag_miner.py`.

## Test your installation

```bash
python -m unittest discover -s 1_classifier/tests -v
python -m unittest discover -s 2_tool_catalog/tests -v
python -m unittest discover -s 3_flag_hunter/tests -v
python 3_flag_hunter/batch.py 3_flag_hunter/challenges --difficulty medium --csv results.csv
```

Missing dependencies cause integration skips, not passes. The installed Sherlock integration contacts public sites; web/TCP tests use local listeners. Batch counts regex candidates, not flags accepted by a competition server. See [validation](docs/VALIDATION.md) for measured coverage and priorities.
