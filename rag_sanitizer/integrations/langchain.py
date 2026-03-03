"""LangChain integration."""

from __future__ import annotations

from typing import Any

from rag_sanitizer.config import SanitizerConfig
from rag_sanitizer.sanitizer import RagSanitizer

try:
    from langchain_core.document_transformers import BaseDocumentTransformer
    from langchain_core.documents import Document
except ImportError:  # pragma: no cover - optional dependency fallback

    class BaseDocumentTransformer:  # type: ignore[no-redef]
        """Fallback base for optional LangChain dependency."""

    class Document:  # type: ignore[no-redef]
        """Fallback document used for tests without LangChain."""

        def __init__(self, page_content: str, metadata: dict | None = None) -> None:
            self.page_content = page_content
            self.metadata = metadata or {}


class RagSanitizerTransformer(BaseDocumentTransformer):
    """Drop-in LangChain transformer for document sanitization."""

    def __init__(self, config: SanitizerConfig | None = None, on_threat: str = "sanitize") -> None:
        """Initialize transformer.

        Args:
            config: Optional sanitizer config.
            on_threat: Policy when threat detected (sanitize/drop/flag).
        """
        self.sanitizer = RagSanitizer(config)
        self.on_threat = on_threat

    def transform_documents(self, documents: list[Document], **kwargs: Any) -> list[Document]:
        """Transform input documents.

        Args:
            documents: LangChain documents.
            **kwargs: Optional kwargs.

        Returns:
            Transformed documents.
        """
        del kwargs
        transformed: list[Document] = []
        for doc in documents:
            result = self.sanitizer.scan(doc.page_content, metadata=doc.metadata)

            if result.is_clean:
                transformed.append(doc)
                continue

            if self.on_threat == "drop":
                continue

            if self.on_threat == "flag":
                doc.metadata["rag_sanitizer_threat_score"] = result.threat_score
                doc.metadata["rag_sanitizer_signals"] = [s.model_dump() for s in result.signals]
                transformed.append(doc)
                continue

            doc.page_content = result.sanitized_text
            doc.metadata["rag_sanitizer_threat_score"] = result.threat_score
            doc.metadata["rag_sanitizer_removed_count"] = result.removed_count
            transformed.append(doc)

        return transformed
