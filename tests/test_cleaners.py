from __future__ import annotations

from rag_sanitizer.cleaners.normalize import normalize_text
from rag_sanitizer.cleaners.strip import strip_segments
from rag_sanitizer.models import Severity, ThreatCategory, ThreatSignal


def mk_signal(start: int, end: int) -> ThreatSignal:
    return ThreatSignal(
        category=ThreatCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        description="x",
        matched_text="x",
        start_index=start,
        end_index=end,
        confidence=0.9,
        rule_id="T",
    )


def test_strip_single_segment() -> None:
    text, removed = strip_segments("abcDEFghi", [mk_signal(3, 6)], "")
    assert text == "abcghi"
    assert removed == 1


def test_strip_with_placeholder() -> None:
    text, removed = strip_segments("abcDEFghi", [mk_signal(3, 6)], "[X]")
    assert text == "abc[X]ghi"
    assert removed == 1


def test_strip_merges_overlaps() -> None:
    text, removed = strip_segments("abcdefghij", [mk_signal(2, 5), mk_signal(4, 8)], "")
    assert text == "abij"
    assert removed == 1


def test_strip_out_of_range_safe() -> None:
    text, removed = strip_segments("abc", [mk_signal(-10, 50)], "")
    assert text == ""
    assert removed == 1


def test_normalize_nfkc() -> None:
    out = normalize_text("Ｆｕｌｌｗｉｄｔｈ")
    assert out == "Fullwidth"


def test_normalize_zero_width_removed() -> None:
    out = normalize_text("a\u200bb")
    assert out == "ab"


def test_normalize_whitespace_collapsed() -> None:
    out = normalize_text("a\n\n\n\n\n b      c")
    assert "\n\n\n" not in out
    assert "      " not in out
