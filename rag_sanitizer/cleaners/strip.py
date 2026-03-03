"""Threat segment stripping utilities."""

from __future__ import annotations

from rag_sanitizer.models import ThreatSignal


def strip_segments(
    text: str, signals: list[ThreatSignal], placeholder: str = ""
) -> tuple[str, int]:
    """Remove/replace threat ranges from text.

    Args:
        text: Original text.
        signals: Threat signals with character ranges.
        placeholder: Replacement string.

    Returns:
        Tuple of sanitized text and number of merged removed ranges.
    """
    if not text or not signals:
        return text, 0

    ranges = sorted(
        (max(0, s.start_index), min(len(text), s.end_index))
        for s in signals
        if s.end_index > s.start_index
    )
    if not ranges:
        return text, 0

    merged: list[tuple[int, int]] = []
    for start, end in ranges:
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))

    out_parts: list[str] = []
    cursor = 0
    for start, end in merged:
        out_parts.append(text[cursor:start])
        if placeholder:
            out_parts.append(placeholder)
        cursor = end
    out_parts.append(text[cursor:])

    sanitized = "".join(out_parts)
    return sanitized, len(merged)
