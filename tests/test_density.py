from __future__ import annotations

from rag_sanitizer.analyzers.density import DensityAnalyzer
from rag_sanitizer.config import SanitizerConfig
from rag_sanitizer.models import ThreatCategory


def test_density_ngram_detects() -> None:
    analyzer = DensityAnalyzer(SanitizerConfig(max_ngram_ratio=0.04))
    text = " ".join(["alpha beta gamma"] * 120)
    signals = analyzer.analyze(text)
    assert any(s.rule_id == "DEN-001" for s in signals)


def test_density_keyword_stuffing() -> None:
    analyzer = DensityAnalyzer(SanitizerConfig(max_word_frequency=0.01))
    text = "security " * 300 + "normal text"
    signals = analyzer.analyze(text)
    assert any(s.rule_id == "DEN-002" for s in signals)


def test_density_window_similarity() -> None:
    analyzer = DensityAnalyzer(SanitizerConfig(window_similarity_threshold=0.7))
    chunk = "shared token repeated phrase " * 20
    text = chunk * 10
    signals = analyzer.analyze(text)
    assert any(s.rule_id == "DEN-003" for s in signals)


def test_density_clean_text() -> None:
    analyzer = DensityAnalyzer(SanitizerConfig())
    text = "The quick brown fox jumps over the lazy dog. " * 4
    signals = analyzer.analyze(text)
    assert not signals


def test_density_empty_text() -> None:
    analyzer = DensityAnalyzer(SanitizerConfig())
    assert analyzer.analyze("") == []


def test_density_category() -> None:
    analyzer = DensityAnalyzer(SanitizerConfig(max_ngram_ratio=0.01))
    signals = analyzer.analyze("abc def ghi " * 100)
    assert signals
    assert all(s.category == ThreatCategory.DENSITY_ATTACK for s in signals)
