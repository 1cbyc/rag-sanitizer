"""Prompt injection analyzer."""

from __future__ import annotations

import re
from collections.abc import Iterable

from rag_sanitizer.analyzers.base import BaseAnalyzer
from rag_sanitizer.models import Severity, ThreatCategory, ThreatSignal
from rag_sanitizer.patterns import INJECTION_RULES

SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

PREFILTER_HINTS = (
    "ignore",
    "instruction",
    "system",
    "developer",
    "override",
    "prompt",
    "dan",
    "from now",
    "forget",
    "restriction",
    "anything now",
    "ethical",
    "jailbreak",
    "function",
    "command",
    "execute",
    "document",
    "begin system",
    "context",
    "api",
    "ignora",
    "oublie",
    "ignoriere",
    "忽略",
    "指令",
    "指示",
    "システム",
)


class InjectionAnalyzer(BaseAnalyzer):
    """Detects prompt injection attempts in document content."""

    VERSION = "1.0.0"

    def __init__(self, minimum_severity: str = "low") -> None:
        """Initialize the analyzer.

        Args:
            minimum_severity: Minimum severity level to emit.
        """
        self.minimum_severity = Severity(minimum_severity)
        self._compiled = [
            {
                "rule_id": rule["rule_id"],
                "regex": re.compile(str(rule["pattern"]), re.IGNORECASE | re.MULTILINE),
                "severity": rule["severity"],
                "confidence": rule["confidence"],
            }
            for rule in INJECTION_RULES
        ]

    def analyze(self, text: str, metadata: dict | None = None) -> list[ThreatSignal]:
        """Analyze text for direct injection patterns.

        Args:
            text: Input text.
            metadata: Optional metadata (unused).

        Returns:
            List of threat signals.
        """
        del metadata
        if not text:
            return []
        lowered = text.lower()
        if not any(hint in lowered for hint in PREFILTER_HINTS):
            return []

        signals: list[ThreatSignal] = []
        for rule in self._compiled:
            severity = rule["severity"]
            if not self._is_allowed(severity):
                continue

            regex = rule["regex"]
            for match in regex.finditer(text):
                start, end = match.span()
                matched = text[start:end][:500]
                signals.append(
                    ThreatSignal(
                        category=ThreatCategory.PROMPT_INJECTION,
                        severity=severity,
                        description=f"Matched injection rule {rule['rule_id']}",
                        matched_text=matched,
                        start_index=start,
                        end_index=end,
                        confidence=float(rule["confidence"]),
                        rule_id=str(rule["rule_id"]),
                    )
                )

        return _dedupe_signals(signals)

    def _is_allowed(self, severity: Severity) -> bool:
        return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[self.minimum_severity]


LEET_MAP = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    }
)


def normalize_leetspeak(text: str) -> str:
    """Normalize common leetspeak substitutions.

    Args:
        text: Input text.

    Returns:
        Normalized text.
    """
    return text.translate(LEET_MAP)


def _dedupe_signals(signals: Iterable[ThreatSignal]) -> list[ThreatSignal]:
    seen: set[tuple[str, int, int]] = set()
    deduped: list[ThreatSignal] = []
    for signal in sorted(signals, key=lambda s: (s.start_index, s.end_index, s.rule_id)):
        key = (signal.rule_id, signal.start_index, signal.end_index)
        if key not in seen:
            deduped.append(signal)
            seen.add(key)
    return deduped
