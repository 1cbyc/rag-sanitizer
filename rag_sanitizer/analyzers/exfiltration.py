"""Data exfiltration payload analyzer."""

from __future__ import annotations

import base64
import re
from urllib.parse import parse_qsl, urlparse

from rag_sanitizer.analyzers.base import BaseAnalyzer
from rag_sanitizer.models import Severity, ThreatCategory, ThreatSignal
from rag_sanitizer.patterns import EXFIL_QUERY_KEYS, SHORTENER_DOMAINS, WEBHOOK_DOMAINS

URL_RE = re.compile(r"https?://[^\s)>'\"]+")
MARKDOWN_IMAGE_RE = re.compile(r"!\[[^\]]*\]\((https?://[^)]+)\)", re.IGNORECASE)
HTML_FETCH_TAG_RE = re.compile(r"<(img|script|iframe)\b[^>]*>", re.IGNORECASE)


class ExfiltrationAnalyzer(BaseAnalyzer):
    """Detect outbound-data exfiltration tricks in documents."""

    VERSION = "1.0.0"

    def analyze(self, text: str, metadata: dict | None = None) -> list[ThreatSignal]:
        """Analyze text for exfiltration patterns.

        Args:
            text: Input text.
            metadata: Optional metadata (unused).

        Returns:
            Threat signals.
        """
        del metadata
        signals: list[ThreatSignal] = []

        for match in MARKDOWN_IMAGE_RE.finditer(text):
            signals.append(
                ThreatSignal(
                    category=ThreatCategory.DATA_EXFILTRATION,
                    severity=Severity.HIGH,
                    description="Markdown image URL may leak prompt/context",
                    matched_text=match.group(0)[:500],
                    start_index=match.start(),
                    end_index=match.end(),
                    confidence=0.92,
                    rule_id="EXF-001",
                )
            )

        for match in HTML_FETCH_TAG_RE.finditer(text):
            signals.append(
                ThreatSignal(
                    category=ThreatCategory.DATA_EXFILTRATION,
                    severity=Severity.HIGH,
                    description="HTML tag may trigger outbound request",
                    matched_text=match.group(0)[:500],
                    start_index=match.start(),
                    end_index=match.end(),
                    confidence=0.88,
                    rule_id="EXF-002",
                )
            )

        for match in URL_RE.finditer(text):
            url = match.group(0)
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()
            params = {k.lower(): v for k, v in parse_qsl(parsed.query, keep_blank_values=True)}

            if params.keys() & EXFIL_QUERY_KEYS:
                signals.append(
                    ThreatSignal(
                        category=ThreatCategory.DATA_EXFILTRATION,
                        severity=Severity.HIGH,
                        description="Suspicious query parameter in URL",
                        matched_text=url[:500],
                        start_index=match.start(),
                        end_index=match.end(),
                        confidence=0.9,
                        rule_id="EXF-003",
                    )
                )

            if any(d in hostname for d in WEBHOOK_DOMAINS):
                signals.append(
                    ThreatSignal(
                        category=ThreatCategory.DATA_EXFILTRATION,
                        severity=Severity.CRITICAL,
                        description="Known webhook/callback domain detected",
                        matched_text=url[:500],
                        start_index=match.start(),
                        end_index=match.end(),
                        confidence=0.97,
                        rule_id="EXF-004",
                    )
                )

            if hostname in SHORTENER_DOMAINS:
                signals.append(
                    ThreatSignal(
                        category=ThreatCategory.DATA_EXFILTRATION,
                        severity=Severity.MEDIUM,
                        description="URL shortener detected",
                        matched_text=url[:500],
                        start_index=match.start(),
                        end_index=match.end(),
                        confidence=0.75,
                        rule_id="EXF-005",
                    )
                )

            if _has_base64_segment(parsed.path) or _has_base64_segment(parsed.query):
                signals.append(
                    ThreatSignal(
                        category=ThreatCategory.DATA_EXFILTRATION,
                        severity=Severity.MEDIUM,
                        description="URL contains base64-looking segment",
                        matched_text=url[:500],
                        start_index=match.start(),
                        end_index=match.end(),
                        confidence=0.72,
                        rule_id="EXF-006",
                    )
                )

        return _dedupe(signals)


def _has_base64_segment(value: str) -> bool:
    for token in re.split(r"[/=&?.-]", value):
        if len(token) < 20:
            continue
        if not re.fullmatch(r"[A-Za-z0-9_+/\\-]+={0,2}", token):
            continue
        try:
            padded = token + "=" * ((4 - len(token) % 4) % 4)
            base64.urlsafe_b64decode(padded)
            return True
        except Exception:
            continue
    return False


def _dedupe(signals: list[ThreatSignal]) -> list[ThreatSignal]:
    seen: set[tuple[int, int, str]] = set()
    out: list[ThreatSignal] = []
    for signal in sorted(signals, key=lambda s: (s.start_index, s.end_index, s.rule_id)):
        key = (signal.start_index, signal.end_index, signal.rule_id)
        if key not in seen:
            out.append(signal)
            seen.add(key)
    return out
