"""
gateway.py
----------
Pipeline Orchestrator — wires all stages together.

Full pipeline:
    User Input
        → InjectionDetector  (threat_detector.py)
        → PIIEngine          (pii_engine.py)
        → PolicyEngine       (policy_engine.py)
        → Output  (ALLOW / MASK / BLOCK)

Also measures latency for the complete pipeline.
"""

import time
from typing import Dict

from threat_detector import InjectionDetector
from pii_engine      import PIIEngine
from policy_engine   import PolicyEngine


class SecurityGateway:
    """Runs every pipeline stage in order and returns a unified result dict."""

    def __init__(self):
        self.injector = InjectionDetector()
        self.pii      = PIIEngine()
        self.policy   = PolicyEngine()

    def process(self, text: str) -> Dict:
        start = time.time()

        # ── Stage 1: Injection Detection ──────────────────────
        inj = self.injector.detect(text)

        # ── Stage 2: PII Detection ─────────────────────────────
        pii_results, composites = self.pii.analyze(text)

        # ── Stage 3: Policy Decision ───────────────────────────
        decision = self.policy.decide(
            injection_flag=inj["is_injection"],
            pii_found=len(pii_results) > 0,
        )

        # ── Stage 4: Output Generation ─────────────────────────
        if decision == "BLOCK":
            output = "[BLOCKED]"
        elif decision == "MASK":
            output = self.pii.anonymize(text, pii_results)
        else:
            output = text

        latency = round((time.time() - start) * 1000, 2)

        return {
            "input":              text,
            "injection_score":    inj["score"],
            "pii_count":          len(pii_results),
            "composite_detected": len(composites),
            "decision":           decision,
            "output":             output,
            "latency_ms":         latency,
        }
