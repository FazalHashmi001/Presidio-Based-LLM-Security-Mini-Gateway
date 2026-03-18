"""
policy_engine.py
----------------
Stage 3 of the pipeline: Policy Decision.

Applies a simple priority-ordered rule set:
  1. Injection detected          → BLOCK   (security always wins)
  2. PII or composite detected   → config.action  (MASK / ALLOW / BLOCK)
  3. Nothing detected            → ALLOW
"""

from settings import config


class PolicyEngine:
    """Translates detection results into an enforcement decision."""

    def decide(self, injection_flag: bool, pii_found: bool) -> str:
        """
        Args:
            injection_flag – True if InjectionDetector flagged the input
            pii_found      – True if PIIEngine found at least one entity

        Returns:
            "BLOCK" | "MASK" | "ALLOW"
        """
        if injection_flag:
            return "BLOCK"
        if pii_found:
            return config.action
        return "ALLOW"
