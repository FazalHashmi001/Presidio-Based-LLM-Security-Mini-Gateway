"""
settings.py
-----------
Central configuration for the LLM Security Gateway.
Change thresholds and behaviour HERE — no other file needs editing.
"""

from dataclasses import dataclass


@dataclass
class Config:
    # ── Injection Detection ──────────────────────────────────
    injection_threshold: float = 0.5   # score >= this → treat as injection

    # ── PII Detection ────────────────────────────────────────
    pii_threshold: float = 0.5         # confidence >= this → treat as PII

    # ── Policy Action ────────────────────────────────────────
    # What to do when PII is found (and NO injection):
    #   ALLOW  → pass text through unchanged
    #   MASK   → anonymise detected PII spans
    #   BLOCK  → reject the entire input
    action: str = "MASK"


# ── Singleton ────────────────────────────────────────────────
# Every other module does:  from settings import config
config = Config()
