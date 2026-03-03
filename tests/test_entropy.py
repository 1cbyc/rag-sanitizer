from __future__ import annotations

import random
import string

from rag_sanitizer.analyzers.entropy import EntropyAnalyzer
from rag_sanitizer.config import SanitizerConfig


def random_blob(length: int = 512) -> str:
    chars = string.ascii_letters + string.digits + "+/="
    return "".join(random.choice(chars) for _ in range(length))


def test_high_entropy_detects() -> None:
    analyzer = EntropyAnalyzer(SanitizerConfig(entropy_threshold=4.0))
    text = random_blob(1024)
    signals = analyzer.analyze(text)
    assert any(s.rule_id == "ENT-001" for s in signals)


def test_high_entropy_ratio_detects() -> None:
    analyzer = EntropyAnalyzer(SanitizerConfig(entropy_threshold=4.0, max_high_entropy_ratio=0.05))
    text = random_blob(2048)
    signals = analyzer.analyze(text)
    assert any(s.rule_id == "ENT-002" for s in signals)


def test_uuid_exclusion() -> None:
    analyzer = EntropyAnalyzer(SanitizerConfig(entropy_threshold=3.0))
    text = "550e8400-e29b-41d4-a716-446655440000 " * 30
    signals = analyzer.analyze(text)
    assert signals == []


def test_hex_color_exclusion() -> None:
    analyzer = EntropyAnalyzer(SanitizerConfig(entropy_threshold=3.0))
    text = "#a1b2c3 #d4e5f6 #ffeedd " * 50
    signals = analyzer.analyze(text)
    assert signals == []


def test_data_uri_exclusion() -> None:
    analyzer = EntropyAnalyzer(SanitizerConfig(entropy_threshold=3.0))
    text = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA " * 20
    signals = analyzer.analyze(text)
    assert signals == []


def test_empty_entropy() -> None:
    analyzer = EntropyAnalyzer(SanitizerConfig())
    assert analyzer.analyze("") == []
