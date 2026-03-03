"""Density and repetition attack analyzer."""

from __future__ import annotations

import re
from collections import Counter

from rag_sanitizer.analyzers.base import BaseAnalyzer
from rag_sanitizer.config import SanitizerConfig
from rag_sanitizer.models import Severity, ThreatCategory, ThreatSignal

WORD_RE = re.compile(r"[\w']+")


class DensityAnalyzer(BaseAnalyzer):
    """Detect repetition-heavy context poisoning attacks."""

    VERSION = "1.0.0"

    def __init__(self, config: SanitizerConfig) -> None:
        """Initialize analyzer with config thresholds.

        Args:
            config: Sanitizer configuration.
        """
        self.config = config

    def analyze(self, text: str, metadata: dict | None = None) -> list[ThreatSignal]:
        """Analyze text density.

        Args:
            text: Input text.
            metadata: Optional metadata (unused).

        Returns:
            Threat signals.
        """
        del metadata
        if not text:
            return []

        words = [w.lower() for w in WORD_RE.findall(text)]
        if len(words) < 5:
            return []

        signals: list[ThreatSignal] = []
        signals.extend(self._analyze_ngrams(words, text))
        signals.extend(self._analyze_keywords(words, text))
        signals.extend(self._analyze_windows(text))
        return signals

    def _analyze_ngrams(self, words: list[str], text: str) -> list[ThreatSignal]:
        if len(words) < 120:
            return []
        ngrams = [" ".join(words[i : i + 3]) for i in range(len(words) - 2)]
        if not ngrams:
            return []

        counts = Counter(ngrams)
        top_ngram, top_count = counts.most_common(1)[0]
        ratio = top_count / len(ngrams)
        if ratio <= self.config.max_ngram_ratio:
            return []

        idx = text.lower().find(top_ngram)
        idx = max(idx, 0)
        return [
            ThreatSignal(
                category=ThreatCategory.DENSITY_ATTACK,
                severity=Severity.HIGH if ratio > 0.15 else Severity.MEDIUM,
                description=f"3-gram repetition ratio {ratio:.2%} exceeded threshold",
                matched_text=top_ngram[:500],
                start_index=idx,
                end_index=idx + len(top_ngram),
                confidence=min(0.99, 0.6 + ratio),
                rule_id="DEN-001",
            )
        ]

    def _analyze_keywords(self, words: list[str], text: str) -> list[ThreatSignal]:
        if len(words) < 200:
            return []
        long_words = [w for w in words if len(w) > 4]
        if not long_words:
            return []

        counts = Counter(long_words)
        word, count = counts.most_common(1)[0]
        ratio = count / len(words)
        if ratio <= self.config.max_word_frequency:
            return []

        idx = text.lower().find(word)
        idx = max(idx, 0)
        return [
            ThreatSignal(
                category=ThreatCategory.DENSITY_ATTACK,
                severity=Severity.MEDIUM,
                description=f"Keyword stuffing ratio {ratio:.2%} exceeded threshold",
                matched_text=word,
                start_index=idx,
                end_index=idx + len(word),
                confidence=min(0.95, 0.55 + ratio),
                rule_id="DEN-002",
            )
        ]

    def _analyze_windows(self, text: str) -> list[ThreatSignal]:
        window_size = 200
        stride = 100
        stop = max(len(text) - window_size + 1, 1)
        windows = [text[i : i + window_size] for i in range(0, stop, stride)]
        if len(windows) < 3:
            return []

        high_sim = 0
        comparisons = 0
        for i in range(len(windows) - 1):
            sim = _shingle_jaccard(windows[i], windows[i + 1])
            comparisons += 1
            if sim > self.config.window_similarity_threshold:
                high_sim += 1

        if comparisons == 0:
            return []

        ratio = high_sim / comparisons
        if ratio <= 0.30:
            return []

        snippet = windows[0][:120]
        return [
            ThreatSignal(
                category=ThreatCategory.DENSITY_ATTACK,
                severity=Severity.HIGH,
                description=f"High duplicate window ratio {ratio:.2%}",
                matched_text=snippet,
                start_index=0,
                end_index=min(len(snippet), len(text)),
                confidence=min(0.98, 0.5 + ratio),
                rule_id="DEN-003",
            )
        ]


def _shingle_jaccard(a: str, b: str, k: int = 5) -> float:
    if len(a) < k or len(b) < k:
        return 0.0
    a_set = {a[i : i + k].lower() for i in range(len(a) - k + 1)}
    b_set = {b[i : i + k].lower() for i in range(len(b) - k + 1)}
    denom = len(a_set | b_set)
    if denom == 0:
        return 0.0
    return len(a_set & b_set) / denom
