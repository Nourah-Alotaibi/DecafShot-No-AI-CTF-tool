"""
evidence.py — the "blackboard". Every tool writes facts here; the ranker
reads it to decide what to run next. This is the shared memory that makes
the engine adaptive without any learning.
"""
from dataclasses import dataclass, field


@dataclass
class Evidence:
    category: str = "misc"          # from your classifier
    difficulty: str = "medium"
    challenge_path: str = ""

    facts: list = field(default_factory=list)     # human-readable findings
    signals: set = field(default_factory=set)     # tags the ranker keys off
    text_blobs: list = field(default_factory=list)  # raw text for flag mining
    ran: set = field(default_factory=set)         # tools already used (memory)
    flag: str | None = None
    steps: int = 0                                 # how many tools were run
    solved_by: str | None = None                   # which tool produced the flag

    def add_fact(self, text: str):
        self.facts.append(text)

    def add_signal(self, *tags: str):
        for t in tags:
            self.signals.add(t)

    def add_text(self, blob: str):
        if blob and blob.strip():
            self.text_blobs.append(blob)

    def has(self, *tags: str) -> bool:
        return any(t in self.signals for t in tags)
