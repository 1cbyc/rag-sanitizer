"""Normalization utilities."""

from __future__ import annotations

import re
import unicodedata

from rag_sanitizer.patterns import HOMOGLYPH_MAP, ZERO_WIDTH_CHARS

ZERO_WIDTH_RE = re.compile(f"[{re.escape(ZERO_WIDTH_CHARS)}]")
MANY_NEWLINES_RE = re.compile(r"\n{4,}")
MANY_SPACES_RE = re.compile(r"[ \t]{6,}")


def normalize_text(text: str, transliterate_confusables: bool = True) -> str:
    """Normalize text for robust analysis.

    Args:
        text: Input text.
        transliterate_confusables: Whether to map known confusable characters.

    Returns:
        Normalized text.
    """
    normalized = unicodedata.normalize("NFKC", text)
    normalized = ZERO_WIDTH_RE.sub("", normalized)

    if transliterate_confusables:
        normalized = "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in normalized)

    normalized = MANY_NEWLINES_RE.sub("\n\n", normalized)
    normalized = MANY_SPACES_RE.sub(" ", normalized)
    return normalized.strip()
