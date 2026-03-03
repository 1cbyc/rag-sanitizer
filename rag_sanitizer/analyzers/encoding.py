"""Encoded payload analyzer."""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
from typing import Callable

from rag_sanitizer.analyzers.base import BaseAnalyzer
from rag_sanitizer.analyzers.injection import InjectionAnalyzer, normalize_leetspeak
from rag_sanitizer.config import SanitizerConfig
from rag_sanitizer.models import Severity, ThreatCategory, ThreatSignal
from rag_sanitizer.patterns import HOMOGLYPH_MAP

BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
HEX_ESCAPE_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
HEX_SPACE_RE = re.compile(r"(?:0x[0-9a-fA-F]{2}[\s,;]*){4,}")
UNICODE_ESCAPE_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){3,}")
HTML_ENTITY_RE = re.compile(r"(?:&#\d{2,5};|&[a-zA-Z]{2,10};){3,}")


class EncodingAnalyzer(BaseAnalyzer):
    """Detect and decode encoded/obfuscated payloads."""

    VERSION = "1.0.0"

    def __init__(self, config: SanitizerConfig) -> None:
        """Initialize analyzer.

        Args:
            config: Sanitizer configuration.
        """
        self.config = config
        self.injection = InjectionAnalyzer(minimum_severity=config.injection_severity_minimum)

    def analyze(self, text: str, metadata: dict | None = None) -> list[ThreatSignal]:
        """Analyze text for encoded payloads.

        Args:
            text: Input text.
            metadata: Optional metadata (unused).

        Returns:
            Threat signals.
        """
        del metadata
        signals: list[ThreatSignal] = []
        if not text:
            return signals

        signals.extend(self._run_pattern_decoder(text, BASE64_RE, self._decode_base64, "ENC-001"))
        signals.extend(
            self._run_pattern_decoder(text, HEX_ESCAPE_RE, self._decode_hex_escapes, "ENC-002")
        )
        signals.extend(
            self._run_pattern_decoder(text, HEX_SPACE_RE, self._decode_hex_space, "ENC-003")
        )
        signals.extend(
            self._run_pattern_decoder(
                text, UNICODE_ESCAPE_RE, self._decode_unicode_escapes, "ENC-004"
            )
        )
        signals.extend(self._run_pattern_decoder(text, HTML_ENTITY_RE, html.unescape, "ENC-005"))

        rot13 = codecs.decode(text, "rot_13")
        if rot13 != text and self.injection.analyze(rot13):
            signals.append(
                ThreatSignal(
                    category=ThreatCategory.ENCODED_PAYLOAD,
                    severity=Severity.HIGH,
                    description="ROT13-decoded text contains injection patterns",
                    matched_text=text[:500],
                    start_index=0,
                    end_index=min(len(text), 200),
                    confidence=0.85,
                    rule_id="ENC-006",
                )
            )

        normalized = _normalize_homoglyphs(normalize_leetspeak(text.lower()))
        if normalized != text.lower() and self.injection.analyze(normalized):
            signals.append(
                ThreatSignal(
                    category=ThreatCategory.UNICODE_SMUGGLING,
                    severity=Severity.HIGH,
                    description="Leetspeak/homoglyph normalized text contains injections",
                    matched_text=text[:500],
                    start_index=0,
                    end_index=min(len(text), 200),
                    confidence=0.9,
                    rule_id="ENC-007",
                )
            )

        return _dedupe(signals)

    def _run_pattern_decoder(
        self,
        text: str,
        pattern: re.Pattern[str],
        decoder: Callable[[str], str],
        rule_id: str,
    ) -> list[ThreatSignal]:
        out: list[ThreatSignal] = []
        for match in pattern.finditer(text):
            token = match.group(0)
            if len(token) < self.config.min_base64_length and rule_id == "ENC-001":
                continue
            decoded = decoder(token)
            if not decoded:
                continue
            nested = self.injection.analyze(decoded)
            if not nested:
                continue
            out.append(
                ThreatSignal(
                    category=ThreatCategory.ENCODED_PAYLOAD,
                    severity=Severity.CRITICAL,
                    description=f"Encoded payload decodes to injection ({rule_id})",
                    matched_text=token[:500],
                    start_index=match.start(),
                    end_index=match.end(),
                    confidence=0.94,
                    rule_id=rule_id,
                )
            )
        return out

    @staticmethod
    def _decode_base64(token: str) -> str:
        try:
            decoded = base64.b64decode(token, validate=True)
            return decoded.decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            return ""

    @staticmethod
    def _decode_hex_escapes(token: str) -> str:
        raw = token.replace("\\x", "")
        try:
            return bytes.fromhex(raw).decode("utf-8", errors="ignore")
        except ValueError:
            return ""

    @staticmethod
    def _decode_hex_space(token: str) -> str:
        pieces = re.findall(r"0x([0-9a-fA-F]{2})", token)
        if not pieces:
            return ""
        try:
            return bytes(int(p, 16) for p in pieces).decode("utf-8", errors="ignore")
        except ValueError:
            return ""

    @staticmethod
    def _decode_unicode_escapes(token: str) -> str:
        try:
            return token.encode("utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            return ""


def _normalize_homoglyphs(text: str) -> str:
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def _dedupe(signals: list[ThreatSignal]) -> list[ThreatSignal]:
    seen: set[tuple[int, int, str]] = set()
    out: list[ThreatSignal] = []
    for signal in sorted(signals, key=lambda s: (s.start_index, s.end_index, s.rule_id)):
        key = (signal.start_index, signal.end_index, signal.rule_id)
        if key not in seen:
            out.append(signal)
            seen.add(key)
    return out
