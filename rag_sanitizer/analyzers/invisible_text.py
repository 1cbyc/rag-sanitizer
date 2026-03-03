"""Invisible text analyzer."""

from __future__ import annotations

import re
from typing import Any

from rag_sanitizer.analyzers.base import BaseAnalyzer
from rag_sanitizer.config import SanitizerConfig
from rag_sanitizer.models import Severity, ThreatCategory, ThreatSignal
from rag_sanitizer.patterns import ZERO_WIDTH_CHARS

ZERO_WIDTH_RE = re.compile(f"[{re.escape(ZERO_WIDTH_CHARS)}]")
WHITESPACE_ABUSE_RE = re.compile(r"[ \t\n\r]{51,}")
HIDDEN_CSS_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*transparent|"
    r"opacity\s*:\s*0|position\s*:\s*absolute\s*;\s*left\s*:\s*-9999px",
    re.IGNORECASE,
)


class InvisibleTextAnalyzer(BaseAnalyzer):
    """Detect hidden or near-invisible text artifacts."""

    VERSION = "1.0.0"

    def __init__(self, config: SanitizerConfig) -> None:
        """Initialize with configured thresholds.

        Args:
            config: Sanitizer configuration.
        """
        self.config = config

    def analyze(self, text: str, metadata: dict | None = None) -> list[ThreatSignal]:
        """Analyze for invisible text vectors.

        Args:
            text: Input text.
            metadata: Parsing metadata.

        Returns:
            Threat signals.
        """
        metadata = metadata or {}
        signals: list[ThreatSignal] = []

        for match in ZERO_WIDTH_RE.finditer(text):
            signals.append(
                ThreatSignal(
                    category=ThreatCategory.INVISIBLE_TEXT,
                    severity=Severity.HIGH,
                    description="Zero-width character detected",
                    matched_text=match.group(0).encode("unicode_escape").decode("ascii"),
                    start_index=match.start(),
                    end_index=match.end(),
                    confidence=0.95,
                    rule_id="INV-001",
                )
            )

        for match in WHITESPACE_ABUSE_RE.finditer(text):
            signals.append(
                ThreatSignal(
                    category=ThreatCategory.INVISIBLE_TEXT,
                    severity=Severity.MEDIUM,
                    description="Excessive whitespace sequence detected",
                    matched_text=match.group(0)[:80].replace("\n", "\\n"),
                    start_index=match.start(),
                    end_index=match.end(),
                    confidence=0.8,
                    rule_id="INV-002",
                )
            )

        for match in HIDDEN_CSS_RE.finditer(text):
            signals.append(
                ThreatSignal(
                    category=ThreatCategory.INVISIBLE_TEXT,
                    severity=Severity.HIGH,
                    description="Hidden CSS pattern detected",
                    matched_text=match.group(0)[:120],
                    start_index=match.start(),
                    end_index=match.end(),
                    confidence=0.9,
                    rule_id="INV-003",
                )
            )

        font_sizes = metadata.get("font_sizes", [])
        for item in font_sizes:
            snippet, size = _font_item(item)
            if size is None:
                continue
            if size < self.config.min_font_size_threshold:
                severity = Severity.CRITICAL
                rule_id = "INV-004"
                desc = "Invisible font size detected"
                conf = 0.97
            elif size < 3.0:
                severity = Severity.HIGH
                rule_id = "INV-005"
                desc = "Micro-text font size detected"
                conf = 0.88
            else:
                continue

            idx = text.find(snippet) if snippet else -1
            start = max(idx, 0)
            end = start + len(snippet) if snippet else start + 1
            signals.append(
                ThreatSignal(
                    category=ThreatCategory.INVISIBLE_TEXT,
                    severity=severity,
                    description=desc,
                    matched_text=(snippet or f"font-size:{size}")[:500],
                    start_index=start,
                    end_index=end,
                    confidence=conf,
                    rule_id=rule_id,
                )
            )

        font_color = metadata.get("font_color")
        background_color = metadata.get("background_color")
        if font_color and background_color and _colors_close(font_color, background_color):
            signals.append(
                ThreatSignal(
                    category=ThreatCategory.INVISIBLE_TEXT,
                    severity=Severity.HIGH,
                    description="Foreground and background colors are nearly identical",
                    matched_text=f"font_color={font_color}, background_color={background_color}"[
                        :500
                    ],
                    start_index=0,
                    end_index=min(1, len(text)),
                    confidence=0.9,
                    rule_id="INV-006",
                )
            )

        return signals


def _font_item(item: Any) -> tuple[str, float | None]:
    if isinstance(item, dict):
        snippet = str(item.get("text", ""))
        size = item.get("size")
        try:
            return snippet, float(size)
        except (TypeError, ValueError):
            return snippet, None
    return "", None


def _colors_close(a: str, b: str) -> bool:
    av = _hex_to_rgb(a)
    bv = _hex_to_rgb(b)
    if av is None or bv is None:
        return a.strip().lower() == b.strip().lower()
    distance = sum(abs(x - y) for x, y in zip(av, bv))
    return distance <= 18


def _hex_to_rgb(value: str) -> tuple[int, int, int] | None:
    v = value.strip().lstrip("#")
    if len(v) == 3:
        v = "".join(ch * 2 for ch in v)
    if len(v) != 6:
        return None
    try:
        return (int(v[0:2], 16), int(v[2:4], 16), int(v[4:6], 16))
    except ValueError:
        return None
