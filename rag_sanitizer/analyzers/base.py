"""Base analyzer interfaces."""

from __future__ import annotations


class BaseAnalyzer:
    """Base class for all analyzers."""

    VERSION = "1.0.0"

    def analyze(self, text: str, metadata: dict | None = None):
        """Analyze text and return threat signals."""
        raise NotImplementedError
