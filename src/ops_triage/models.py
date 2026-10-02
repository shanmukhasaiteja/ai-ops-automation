from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator

SEVERITIES = ("P1", "P2", "P3", "P4")
CATEGORIES = ("infrastructure", "security", "data_quality", "access_request", "bug", "billing", "noise", "unclassified")
Severity = Literal["P1", "P2", "P3", "P4"]
Category = Literal[
    "infrastructure", "security", "data_quality", "access_request", "bug", "billing", "noise", "unclassified"
]


def rank(severity: str) -> int:
    """P1 -> 1 (most severe) ... P4 -> 4."""
    return int(severity[1])


def severity_for(rank_value: int) -> str:
    return f"P{min(4, max(1, rank_value))}"


class Event(BaseModel):
    """A normalised alert or ticket, whatever system it came from."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    source: str
    title: str = Field(min_length=1, max_length=300)
    body: str = Field(default="", max_length=20_000)
    service: str | None = None
    reported_severity: Severity | None = None
    labels: dict[str, str] = Field(default_factory=dict)
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def fingerprint(self) -> str:
        """Same alert, different numbers (5xx rate 12% vs 14%) => same fingerprint."""
        normalised = re.sub(r"\d+", "#", self.title.lower()).strip()
        return hashlib.sha256(f"{self.source}|{self.service or ''}|{normalised}".encode()).hexdigest()[:16]


class Triage(BaseModel):
    category: Category
    severity: Severity
    summary: str = Field(max_length=300)
    team: str = Field(max_length=60)
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(default="", max_length=600)
    runbook: str | None = None
    needs_human: bool = False
    policy_notes: list[str] = Field(default_factory=list)

    @field_validator("summary", mode="before")
    @classmethod
    def _clip_summary(cls, value):
        return str(value)[:300] if value is not None else value

    @field_validator("reasoning", mode="before")
    @classmethod
    def _clip_reasoning(cls, value):
        return str(value)[:600] if value is not None else value
