"""LlamaIndex integration."""

from __future__ import annotations

from typing import Any

from rag_sanitizer.config import SanitizerConfig
from rag_sanitizer.sanitizer import RagSanitizer

try:
    from llama_index.core.postprocessor.types import BaseNodePostprocessor
except ImportError:  # pragma: no cover - optional dependency fallback

    class BaseNodePostprocessor:  # type: ignore[no-redef]
        """Fallback base for optional LlamaIndex dependency."""


class RagSanitizerPostprocessor(BaseNodePostprocessor):
    """LlamaIndex node postprocessor for sanitization."""

    sanitizer: RagSanitizer | None = None
    on_threat: str = "sanitize"

    def __init__(self, config: SanitizerConfig | None = None, on_threat: str = "sanitize") -> None:
        """Initialize postprocessor.

        Args:
            config: Optional sanitizer config.
            on_threat: Policy when threat detected (sanitize/drop/flag).
        """
        super().__init__()
        self.sanitizer = RagSanitizer(config)
        self.on_threat = on_threat

    def _postprocess_nodes(self, nodes: list[Any], query_bundle: Any = None) -> list[Any]:
        """Process nodes according to threat policy.

        Args:
            nodes: Input nodes.
            query_bundle: Optional query bundle.

        Returns:
            Processed nodes.
        """
        del query_bundle
        processed: list[Any] = []
        for node in nodes:
            text = node.node.text
            metadata = getattr(node.node, "metadata", {})
            result = self.sanitizer.scan(text, metadata=metadata)

            if result.is_clean:
                processed.append(node)
                continue

            if self.on_threat == "drop":
                continue

            if self.on_threat == "flag":
                node.node.metadata["rag_sanitizer_threat_score"] = result.threat_score
                processed.append(node)
                continue

            node.node.text = result.sanitized_text
            node.node.metadata["rag_sanitizer_threat_score"] = result.threat_score
            processed.append(node)

        return processed
