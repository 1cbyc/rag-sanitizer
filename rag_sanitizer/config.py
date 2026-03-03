"""Configuration models for rag_sanitizer."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SanitizerConfig(BaseModel):
    """Configuration options for :class:`RagSanitizer`."""

    threat_threshold: float = Field(default=0.3, ge=0.0, le=1.0)
    max_text_length: int = 500_000

    density_enabled: bool = True
    max_ngram_ratio: float = Field(default=0.05, ge=0.0, le=1.0)
    max_word_frequency: float = Field(default=0.02, ge=0.0, le=1.0)
    window_similarity_threshold: float = Field(default=0.85, ge=0.0, le=1.0)

    invisible_text_enabled: bool = True
    min_font_size_threshold: float = 1.0
    max_whitespace_sequence: int = 50

    injection_enabled: bool = True
    injection_severity_minimum: str = "low"

    encoding_enabled: bool = True
    min_base64_length: int = 20

    exfiltration_enabled: bool = True

    entropy_enabled: bool = True
    entropy_window_size: int = 256
    entropy_threshold: float = Field(default=4.5, ge=0.0, le=8.0)
    max_high_entropy_ratio: float = Field(default=0.15, ge=0.0, le=1.0)

    strip_placeholder: str = "[REMOVED BY RAG-SANITIZER]"
    normalize_unicode: bool = True
