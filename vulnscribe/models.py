from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class InputType(StrEnum):
    SOURCE_CODE = "source_code"
    HTTP_RESPONSE = "http_response"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScanTarget(BaseModel):
    input_type: InputType
    filename: str = "pasted-input"
    language: str | None = None
    source: str
    metadata: dict[str, str] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: f"VS-{uuid4().hex[:10].upper()}")
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: str = "medium"
    cwe_id: str | None = None
    owasp_category: str | None = None
    affected_component: str
    line_start: int | None = None
    line_end: int | None = None
    evidence: str
    remediation: str
    references: list[str] = Field(default_factory=list)
    scanner: str
    cvss_version: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    validation_status: str = "needs_review"


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: f"scan-{uuid4().hex[:12]}")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target: dict[str, str | None]
    findings: list[Finding]
    summary: dict[str, int]
    warnings: list[str] = Field(default_factory=list)


class CodeScanRequest(BaseModel):
    filename: str = Field(default="pasted-code.txt", max_length=255)
    language: str | None = Field(default=None, max_length=30)
    source: str = Field(min_length=1, max_length=500_000)
    @field_validator("source")
    @classmethod
    def source_must_not_be_whitespace(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("source must not be empty or whitespace")
        return value


class HttpScanRequest(BaseModel):
    raw_response: str = Field(min_length=1, max_length=200_000)
    target_label: str = Field(default="pasted-http-response", max_length=255)
    transport_scheme: Literal["http", "https"] | None = Field(
        default=None,
        description="Transport scheme for the captured response; required to evaluate HSTS applicability.",
    )

    @field_validator("transport_scheme", mode="before")
    @classmethod
    def normalize_transport_scheme(cls, value: str | None) -> str | None:
        return value.lower() if isinstance(value, str) else value

    @field_validator("raw_response")
    @classmethod
    def response_must_not_be_whitespace(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("raw_response must not be empty or whitespace")
        return value
