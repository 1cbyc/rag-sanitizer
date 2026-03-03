"""Data models for scan results and threat signals."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class ThreatCategory(str, Enum):
    """Supported threat categories."""

    PROMPT_INJECTION = "prompt_injection"
    INVISIBLE_TEXT = "invisible_text"
    DENSITY_ATTACK = "density_attack"
    ENCODED_PAYLOAD = "encoded_payload"
    DATA_EXFILTRATION = "data_exfiltration"
    UNICODE_SMUGGLING = "unicode_smuggling"
    HIGH_ENTROPY_BLOB = "high_entropy_blob"


class Severity(str, Enum):
    """Threat severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatSignal(BaseModel):
    """A single analyzer finding."""

    category: ThreatCategory
    severity: Severity
    description: str
    matched_text: str = Field(max_length=500)
    start_index: int
    end_index: int
    confidence: float = Field(ge=0.0, le=1.0)
    rule_id: str


class ScanResult(BaseModel):
    """Aggregated scan result for a document."""

    is_clean: bool
    threat_score: float = Field(ge=0.0, le=1.0)
    signals: list[ThreatSignal]
    signal_count: int
    sanitized_text: str
    original_length: int
    sanitized_length: int
    removed_count: int
    processing_time_ms: float
    analyzer_versions: dict[str, str]
