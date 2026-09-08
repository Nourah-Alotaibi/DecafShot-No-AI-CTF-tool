# DecafShot

**Decaffeinated. De-AI'd CTF kit.**

Three parts that fit together. All deterministic — no generative model
required to run the engine, no internet needed at solve time.

## 1_classifier/
Given a challenge, returns its category (web/crypto/pwn/...) using a rule
engine + small offline ML classifier. Feeds the category into part 3.
    python classifier.py --text "RSA public key, recover the flag"

## 2_tool_catalog/
Auto-collects the top GitHub security tools per category, ranked by
stars x recency, filtered for relevance. Feeds the tool list into part 3.
    python collect_tools.py        # regenerates tools_catalog.*

## 3_flag_hunter/
The engine. Takes category + difficulty, then loops: score every tool by
(base weight x evidence fit) -> run the top one -> update evidence -> re-score,
until it finds CYF{...}. The re-scoring after each step is the adaptivity —
with zero learning. This loop is the research contribution.
    python run.py --path ./challenge.txt --category crypto --difficulty easy

## The pipeline
    challenge --> [1] classify category --> [3] engine ranks & runs tools
                  [2] supplies the tool list          |
                                                       v
                                                    CYF{flag}

## Where your originality sits
Multi-category + adaptive + fully rule/ML-based (no generative model), all at
once. Existing tools do only two of the three (Zeratool/autorop:
adaptive+non-generative but pwn-only; Katana: multi-category+non-generative
but fixed order; autonomous solving agents: multi-category+adaptive but rely
on a generative model). See 1_classifier/RELATED_WORK.md for the full
prior-art map.

## Setup (do this on your machine)
On Windows, work inside WSL (`wsl --install -d Ubuntu`) — the security tools
are Unix-first.
    sudo apt install -y python3 python3-pip file binutils binwalk exiftool
    pip3 install scikit-learn joblib      # for the classifier
Then wire the two real solvers when ready (commands in 3_flag_hunter/cyf/tools.py):
    git clone https://github.com/RsaCtfTool/RsaCtfTool
    pip3 install zeratool
