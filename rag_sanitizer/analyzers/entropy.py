"""Entropy-based analyzer for obfuscated blobs."""

from __future__ import annotations

import math
import re
from collections import Counter

from rag_sanitizer.analyzers.base import BaseAnalyzer
from rag_sanitizer.config import SanitizerConfig
from rag_sanitizer.models import Severity, ThreatCategory, ThreatSignal

UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
HEX_COLOR_RE = re.compile(r"#[0-9a-fA-F]{6}\b")
DATA_URI_RE = re.compile(r"data:image/[a-zA-Z]+;base64,[A-Za-z0-9+/=]+")


class EntropyAnalyzer(BaseAnalyzer):
    """Detect high-entropy obfuscated payload segments."""

    VERSION = "1.0.0"

    def __init__(self, config: SanitizerConfig) -> None:
        """Initialize analyzer.

        Args:
            config: Sanitizer configuration.
        """
        self.config = config

    def analyze(self, text: str, metadata: dict | None = None) -> list[ThreatSignal]:
        """Run entropy detection using sliding windows.

        Args:
            text: Input text.
            metadata: Optional metadata (unused).

        Returns:
            Threat signals.
        """
        del metadata
        if not text:
            return []

        window = self.config.entropy_window_size
        stride = max(1, window // 2)
        if len(text) < window:
            windows = [(0, text)]
        else:
            windows = [(i, text[i : i + window]) for i in range(0, len(text) - window + 1, stride)]

        high: list[tuple[int, str, float]] = []
        total = 0
        for start, chunk in windows:
            if _benign_high_entropy(chunk):
                continue
            ent = _shannon_entropy(chunk)
            total += 1
            if ent > self.config.entropy_threshold:
                high.append((start, chunk, ent))

        if total == 0:
            return []

        signals: list[ThreatSignal] = []
        for start, chunk, ent in high[:5]:
            signals.append(
                ThreatSignal(
                    category=ThreatCategory.HIGH_ENTROPY_BLOB,
                    severity=Severity.MEDIUM if ent < 5.5 else Severity.HIGH,
                    description=f"High entropy window ({ent:.2f})",
                    matched_text=chunk[:500],
                    start_index=start,
                    end_index=min(len(text), start + len(chunk)),
                    confidence=min(0.95, (ent - self.config.entropy_threshold) / 3 + 0.6),
                    rule_id="ENT-001",
                )
            )

        ratio = len(high) / total
        if ratio > self.config.max_high_entropy_ratio:
            signals.append(
                ThreatSignal(
                    category=ThreatCategory.HIGH_ENTROPY_BLOB,
                    severity=Severity.HIGH,
                    description=f"High entropy window ratio {ratio:.2%}",
                    matched_text=text[:500],
                    start_index=0,
                    end_index=min(len(text), 256),
                    confidence=min(0.99, 0.65 + ratio),
                    rule_id="ENT-002",
                )
            )

        return signals


def _shannon_entropy(text: str) -> float:
    data = text.encode("utf-8", errors="ignore")
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _benign_high_entropy(chunk: str) -> bool:
    return bool(UUID_RE.search(chunk) or HEX_COLOR_RE.search(chunk) or DATA_URI_RE.search(chunk))
