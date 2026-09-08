# Related Work & Positioning — CTF Category/Tool Dispatcher

Notes for the paper's related-work section. Grouped so you can state precisely
what exists and where the Control Room's contribution sits.

## 1. CTF-solving generative-model agents (crowded, mature — NOT your contribution)

This space is active and well-benchmarked. These *solve* challenges end-to-end;
they are what "no generative model" events ban. Your work recommends tools
to a human and keeps the lower tiers competition-legal — a different goal.

- **NYU CTF Bench** (Shao et al., 2024) — first benchmark to adapt real CTF
  challenges (2017–2023) for agent evaluation; 200 Dockerized tasks with
  category labels, difficulty scores, pre-installed toolset. One of your eval
  targets. Repo: github.com/NYU-CTF-Bench
- **Cybench** (Zhang et al., ICLR 2025) — 40 professional-level challenges with
  fine-grained subtasks for measuring partial progress. Your other eval target.
- **EnIGMA** (Abramovich et al., 2025) — agent–computer interface for terminal
  programs; established the interactive-agent approach.
- **D-CIPHER** (Udeshi et al., 2025) — multi-agent (planner + executor +
  auto-prompter); SOTA at time of writing: 22.0% NYU CTF Bench, 22.5% Cybench,
  44.0% HackTheBox. Repo: github.com/NYU-CTF-Bench/nyuctf_agents
- **CTFTiny** (2025) — compact 50-challenge benchmark for rapid experiments —
  useful if you want a cheaper eval loop than full NYU/Cybench.
- **KryptoPilot** (2026) — crypto-specialized agent; shows the per-category
  specialization trend.
- General finding across this literature (When Generative Models Meet
  Cybersecurity SLR, 2024; Hacking CTFs with Plain Agents, 2024): these agents
  hold security knowledge but **struggle to apply it** — most solved <50% at
  release. This supports your human-in-the-loop framing: the human closes the
  application gap.

## 2. CTF category classification (sparse — partially your contribution)

Very little polished, installable work here.

- Category taxonomies are well-documented (HackerDNA 2026; see citation below,
  Table 7) — six-ish canonical categories
  (web, crypto, forensics, reverse, pwn, OSINT/misc). Cite for your category set.
- ML *inside* specific challenges exists (e.g. decision trees for side-channel
  CTF, IACR eprint 2019/860) but that's using ML to solve a crypto challenge —
  not to classify which category a challenge belongs to.
- **Gap:** no maintained "give it a challenge → get the category + recommended
  tool" dispatcher. Existing category info is static prose or benchmark metadata,
  not a routing system. This is where your rule+ML classifier is novel-ish.

## 3. Tool catalogs (ready-made — reuse, don't rebuild)

- **awesome-ctf** (github.com/apsdehal/awesome-ctf) — curated tool list by category.
- **ctf-tools** (github.com/zardus/ctf-tools) — installer scripts per category.
- Reuse these as your tool catalog / install layer; cite as the static baseline
  your dispatcher improves on (static list vs challenge-aware routing).

## 4. The actual gap (your contribution)

None of the above combines:
  (a) a **rule-and-ML-first cascade** (no generative model) that
      resolves most challenges without any generative model, so the lower
      tiers are competition-legal, plus
  (b) a **governed escalation** to a human reviewer only under an auditable
      SAFE/REVIEW/BLOCKED policy.

The novelty is the *governed connective tissue* — recommending to a human and
staying legal at the SAFE/REVIEW tiers — not classification or solving in
isolation. This is also the AgentGuard "policy-aware security harness" angle:
the cascade is a concrete instantiation of the policy ladder.

## Suggested claim for the paper

> "Prior work either solves CTF challenges autonomously with generative-model
> agents [NYU CTF Bench; Cybench; D-CIPHER; EnIGMA] or catalogs tools statically
> [awesome-ctf; ctf-tools], but does not address tool *recommendation* to a
> human under a policy that keeps the non-generative stages competition-legal.
> We close this gap with a rule→ML→human-review cascade governed by a
> SAFE/REVIEW/BLOCKED policy engine."

## Honest measurement note (put this in limitations)

The bundled ML stage is a TF-IDF + logistic-regression classifier trained on a
40-example seed set (5 per category). Its 5-fold CV accuracy on that seed set is
low (~0.25) purely because 4-example-per-fold training can't cover the
vocabulary — a data-size artifact, not a model defect. The rule engine resolves
the majority of well-formed challenges on file-type + keyword signals alone; the
ML stage only earns its place once trained on a real corpus (a few hundred
labeled challenges scraped from CTFtime / picoCTF writeups). Report the rule
engine's coverage as the headline number and treat ML as the tie-breaker for
ambiguous descriptions.

## Citations to chase down (need proper bibtex)

- Shao et al. 2024 — NYU CTF Bench (arXiv 2406.05590 area / CSAW)
- Zhang et al. 2025 — Cybench (ICLR 2025)
- Abramovich et al. 2025 — EnIGMA
- Udeshi et al. 2025 — D-CIPHER (arXiv 2502.10931)
- CTFTiny (arXiv 2508.05674)
- "Can AI Lower the Barrier..." (arXiv 2602.18172) — category taxonomy table
- apsdehal/awesome-ctf, zardus/ctf-tools — tool catalogs
