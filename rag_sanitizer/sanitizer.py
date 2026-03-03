"""Core RagSanitizer implementation."""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable

from rag_sanitizer.analyzers.density import DensityAnalyzer
from rag_sanitizer.analyzers.encoding import EncodingAnalyzer
from rag_sanitizer.analyzers.entropy import EntropyAnalyzer
from rag_sanitizer.analyzers.exfiltration import ExfiltrationAnalyzer
from rag_sanitizer.analyzers.injection import InjectionAnalyzer
from rag_sanitizer.analyzers.invisible_text import InvisibleTextAnalyzer
from rag_sanitizer.cleaners.normalize import normalize_text
from rag_sanitizer.cleaners.strip import strip_segments
from rag_sanitizer.config import SanitizerConfig
from rag_sanitizer.models import ScanResult, Severity, ThreatSignal

logger = logging.getLogger("rag_sanitizer")

SEVERITY_WEIGHTS = {
    Severity.INFO: 0.05,
    Severity.LOW: 0.15,
    Severity.MEDIUM: 0.35,
    Severity.HIGH: 0.65,
    Severity.CRITICAL: 0.95,
}


class RagSanitizer:
    """Scan and sanitize untrusted RAG ingestion content."""

    def __init__(self, config: SanitizerConfig | None = None):
        """Initialize sanitizer.

        Args:
            config: Optional config override.
        """
        self.config = config or SanitizerConfig()
        self._analyzers = self._build_analyzers()

    def scan(self, text: str, metadata: dict | None = None) -> ScanResult:
        """Run all enabled analyzers and return a structured scan result.

        Args:
            text: Raw document text.
            metadata: Optional metadata from source parsers.

        Returns:
            Scan result.
        """
        started = time.perf_counter()
        metadata = metadata or {}
        safe_input = text or ""
        analysis_text = safe_input
        if len(analysis_text) > self.config.max_text_length:
            analysis_text = analysis_text[: self.config.max_text_length]
            logger.warning("Input exceeded max_text_length and was truncated")

        signals: list[ThreatSignal] = []
        analyzer_versions: dict[str, str] = {}
        for name, analyzer in self._analyzers:
            analyzer_versions[name] = analyzer.VERSION
            signals.extend(analyzer.analyze(analysis_text, metadata=metadata))

        sanitized, removed_count = strip_segments(
            analysis_text,
            signals,
            self.config.strip_placeholder,
        )
        if self.config.normalize_unicode:
            sanitized = normalize_text(sanitized)
        threat_score = self._score(signals)
        elapsed_ms = (time.perf_counter() - started) * 1000

        return ScanResult(
            is_clean=threat_score < self.config.threat_threshold,
            threat_score=threat_score,
            signals=signals,
            signal_count=len(signals),
            sanitized_text=sanitized,
            original_length=len(safe_input),
            sanitized_length=len(sanitized),
            removed_count=removed_count,
            processing_time_ms=elapsed_ms,
            analyzer_versions=analyzer_versions,
        )

    def sanitize(self, text: str, metadata: dict | None = None) -> str:
        """Scan and return sanitized text.

        Args:
            text: Raw input text.
            metadata: Optional metadata.

        Returns:
            Sanitized text.
        """
        return self.scan(text, metadata=metadata).sanitized_text

    def scan_batch(self, texts: list[str]) -> list[ScanResult]:
        """Run scan on a batch of documents.

        Args:
            texts: Input documents.

        Returns:
            Scan results.
        """
        return [self.scan(text) for text in texts]

    def _build_analyzers(self) -> tuple[tuple[str, object], ...]:
        analyzers: list[tuple[str, object]] = []
        if self.config.density_enabled:
            analyzers.append(("density", DensityAnalyzer(self.config)))
        if self.config.invisible_text_enabled:
            analyzers.append(("invisible_text", InvisibleTextAnalyzer(self.config)))
        if self.config.injection_enabled:
            analyzers.append(
                (
                    "injection",
                    InjectionAnalyzer(minimum_severity=self.config.injection_severity_minimum),
                )
            )
        if self.config.encoding_enabled:
            analyzers.append(("encoding", EncodingAnalyzer(self.config)))
        if self.config.exfiltration_enabled:
            analyzers.append(("exfiltration", ExfiltrationAnalyzer()))
        if self.config.entropy_enabled:
            analyzers.append(("entropy", EntropyAnalyzer(self.config)))
        return tuple(analyzers)

    @staticmethod
    def _score(signals: Iterable[ThreatSignal]) -> float:
        signals = list(signals)
        if not signals:
            return 0.0
        max_sev = max(SEVERITY_WEIGHTS[s.severity] for s in signals)
        confidence = sum(s.confidence for s in signals) / len(signals)
        count_factor = min(1.0, len(signals) / 12)
        score = (0.5 * max_sev) + (0.35 * confidence) + (0.15 * count_factor)
        return max(0.0, min(1.0, score))
