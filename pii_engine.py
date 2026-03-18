"""
pii_engine.py
-------------
Stage 2 of the pipeline: PII Detection & Anonymisation.

Wraps Microsoft Presidio with four customisations:
  1. Custom recognizers  — API_KEY, INTERNAL_ID, PHONE_CUSTOM
  2. Context-aware scoring — boosts confidence when sensitive keywords appear
  3. Composite entity detection — IDENTITY_BUNDLE (name + phone co-occurring)
  4. Confidence calibration — clamp to [0,1] and filter by pii_threshold
"""

from typing import Dict, List, Tuple

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine

from settings import config


class PIIEngine:
    """Detects and optionally anonymises PII using Presidio."""

    def __init__(self):
        self.analyzer   = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        self._register_custom_recognizers()

    # ── 1. Custom Recognizers ────────────────────────────────

    def _register_custom_recognizers(self):
        """Add three domain-specific pattern recognizers to Presidio."""

        # API Key  (e.g. sk-abc123…)
        api_recognizer = PatternRecognizer(
            supported_entity="API_KEY",
            patterns=[Pattern("api_key_pattern", r"sk-[A-Za-z0-9]{16,32}", 0.6)],
        )

        # Internal employee ID  (e.g. EMP-1234)
        id_recognizer = PatternRecognizer(
            supported_entity="INTERNAL_ID",
            patterns=[Pattern("internal_id_pattern", r"EMP-\d{4}", 0.6)],
        )

        # Pakistani mobile number  (e.g. +923001234567)
        phone_recognizer = PatternRecognizer(
            supported_entity="PHONE_CUSTOM",
            patterns=[Pattern("phone_pattern", r"\+92\d{10}", 0.6)],
        )

        self.analyzer.registry.add_recognizer(api_recognizer)
        self.analyzer.registry.add_recognizer(id_recognizer)
        self.analyzer.registry.add_recognizer(phone_recognizer)

    # ── 2 & 4. Context-Aware Scoring + Confidence Calibration ──

    def _adjust_confidence(self, text: str, results: list) -> list:
        """
        Context-aware scoring:
          • Boost score by +0.1 when sensitive keywords ('password', 'secret')
            appear in the same text as a detected entity.

        Confidence calibration:
          • Clamp all scores to [0.0, 1.0].
          • Drop entities whose final score falls below pii_threshold.
        """
        adjusted = []
        for r in results:
            score = r.score

            # Context boost
            if "password" in text.lower() or "secret" in text.lower():
                score += 0.1

            # Calibration: clamp then threshold
            score = min(score, 1.0)
            if score >= config.pii_threshold:
                r.score = score
                adjusted.append(r)

        return adjusted

    # ── 3. Composite Entity Detection ────────────────────────

    def _detect_composite(self, text: str) -> List[Dict]:
        """
        Raises a high-confidence IDENTITY_BUNDLE flag when the text
        contains both a name reference and a phone reference together —
        a combination more sensitive than either piece alone.
        """
        composites = []
        if "name" in text.lower() and "phone" in text.lower():
            composites.append({
                "entity_type": "IDENTITY_BUNDLE",
                "score":       0.8,
            })
        return composites

    # ── Public API ────────────────────────────────────────────

    def analyze(self, text: str) -> Tuple[list, List[Dict]]:
        """Run full PII analysis; return (calibrated_results, composites)."""
        raw_results = self.analyzer.analyze(text=text, language="en")
        calibrated  = self._adjust_confidence(text, raw_results)
        composites  = self._detect_composite(text)
        return calibrated, composites

    def anonymize(self, text: str, results: list) -> str:
        """Replace detected PII spans with anonymised placeholders."""
        return self.anonymizer.anonymize(text=text, analyzer_results=results).text
