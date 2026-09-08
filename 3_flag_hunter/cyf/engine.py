"""
engine.py — the orchestration loop. This is the whole contribution:

    while budget left and no flag:
        rank applicable tools by (base weight x evidence fit)
        run the top one
        it writes new facts/signals into evidence
        check the flag miner
        loop  ->  the ranking is now different because evidence changed

No generative model anywhere. The adaptivity comes purely from evidence changing the scores.
"""
from .config import DIFFICULTY
from .evidence import Evidence
from .flag_miner import find_flag
from .ranker import score_tools
from .tools import REGISTRY


def hunt(category: str, difficulty: str, challenge_path: str, verbose=True):
    budget = DIFFICULTY.get(difficulty, DIFFICULTY["medium"])
    ev = Evidence(category=category, difficulty=difficulty,
                  challenge_path=challenge_path)
    log = []

    def say(msg):
        log.append(msg)
        if verbose:
            print(msg)

    say(f"== CYF Flag Hunter ==  category={category}  difficulty={difficulty}")
    say(f"   budget: {budget['max_steps']} steps, {budget['timeout']}s/tool\n")

    for step in range(1, budget["max_steps"] + 1):
        ranked = score_tools(REGISTRY, ev)
        if not ranked:
            say("no applicable tools left."); break

        # show the current ranking (the explainable part)
        say(f"[step {step}] ranking:")
        for t, s, why in ranked[:4]:
            say(f"    {s:>5}  {t.name:15} {why}")

        tool, s, _ = ranked[0]
        say(f"  -> run {tool.name}")
        tool.run(ev, budget["timeout"])
        ev.ran.add(tool.name)
        ev.steps = step

        # after any tool, sweep all collected text for a flag
        if not ev.flag:
            for blob in ev.text_blobs:
                f = find_flag(blob)
                if f:
                    ev.flag = f; break
        if ev.flag and not ev.solved_by:
            ev.solved_by = tool.name

        for fact in ev.facts[-3:]:
            say(f"       · {fact}")
        say("")

        if ev.flag:
            say(f"*** FLAG FOUND: {ev.flag}  (in {step} steps) ***")
            return ev, log

    say("no flag within budget. Evidence collected:")
    for f in ev.facts:
        say(f"   · {f}")
    return ev, log
