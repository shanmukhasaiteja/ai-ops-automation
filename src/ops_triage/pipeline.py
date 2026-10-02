"""End to end: sanitise -> de-duplicate -> triage -> policy -> route -> audit."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from .catalog import Catalog
from .llm import LLMClient
from .models import Event, Triage
from .policy import apply_policy
from .router import Router
from .security import redact
from .store import Store
from .tools import build_tools
from .triage import triage_event


@dataclass
class Outcome:
    status: str   # processed | duplicate
    event_id: str
    triage: Triage | None = None
    deliveries: list[dict] | None = None
    redacted: list[str] | None = None

    def to_dict(self) -> dict:
        return {"status": self.status, "event_id": self.event_id,
                "triage": self.triage.model_dump() if self.triage else None,
                "deliveries": self.deliveries or [], "redacted": self.redacted or []}


class Pipeline:
    def __init__(self, store: Store, llm: LLMClient, catalog: Catalog, router: Router, dedupe_window: int = 900,
                 confidence_threshold: float = 0.6, redact_ips: bool = False):
        self.store, self.llm, self.catalog, self.router = store, llm, catalog, router
        self.tools = build_tools(catalog, store)
        self.dedupe_window, self.confidence_threshold, self.redact_ips = dedupe_window, confidence_threshold, redact_ips

    def _sanitise(self, event: Event) -> tuple[Event, list[str]]:
        title, k1 = redact(event.title, self.redact_ips)
        body, k2 = redact(event.body, self.redact_ips)
        return event.model_copy(update={"title": title, "body": body}), sorted(set(k1) | set(k2))

    def process(self, event: Event) -> Outcome:
        safe, redacted = self._sanitise(event)   # secrets and PII never reach the LLM or the database
        since = safe.received_at - timedelta(seconds=self.dedupe_window)
        duplicate = self.store.find_recent_duplicate(safe.fingerprint, since)
        if duplicate:
            self.store.bump_duplicate(duplicate)
            return Outcome("duplicate", duplicate)

        self.store.add_event(safe)
        proposed, trace = triage_event(safe, self.llm, self.tools)
        if redacted:
            trace.append({"redacted": redacted})
        final = apply_policy(safe, proposed, self.catalog, self.confidence_threshold)
        self.store.add_triage(safe.id, final, trace)
        return Outcome("processed", safe.id, final, self.router.dispatch(safe, final), redacted)
