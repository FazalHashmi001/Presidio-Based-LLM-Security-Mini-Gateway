"""
threat_detector.py
------------------
Stage 1 of the pipeline: Prompt-Injection Detection.

Scans incoming text against a dictionary of weighted regex patterns.
Returns a risk score (0.0 – 1.0) and a boolean injection flag.
"""

import re
from typing import Dict
from settings import config


# Weighted injection patterns — add / tune entries here freely
INJECTION_PATTERNS: Dict[str, float] = {
    r"ignore previous instructions": 0.5,
    r"bypass":                        0.4,
    r"jailbreak":                     0.6,
    r"system prompt":                 0.4,
    r"override security":             0.5,
}


class InjectionDetector:
    """Scores text for prompt-injection attempts using weighted regex matching."""

    def score(self, text: str) -> float:
        """Sum pattern weights for every match; cap at 1.0."""
        total = 0.0
        for pattern, weight in INJECTION_PATTERNS.items():
            if re.search(pattern, text, re.IGNORECASE):
                total += weight
        return min(total, 1.0)

    def detect(self, text: str) -> Dict:
        """
        Returns:
            score        – float risk score
            is_injection – True if score >= injection_threshold
        """
        s = self.score(text)
        return {
            "score":        s,
            "is_injection": s >= config.injection_threshold,
        }
