"""Rule-based routing and reliable webhook delivery (retries with backoff, failures kept for retry)."""
from __future__ import annotations

import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import yaml

from .models import Event, Triage
from .store import Store

EMOJI = {"P1": "🚨", "P2": "🔴", "P3": "🟠", "P4": "🔵"}
PD_SEVERITY = {"P1": "critical", "P2": "error", "P3": "warning", "P4": "info"}
KNOWN_CONDITIONS = {"severity", "category", "needs_human"}
_ENV = re.compile(r"\$\{(\w+)\}")


def _expand(value):
    return _ENV.sub(lambda m: os.environ.get(m.group(1), ""), value) if isinstance(value, str) else value


# ------------------------------------------------------------------ payload formats (no secrets in here)
def fmt_slack(event: Event, t: Triage, dest: Destination) -> dict:
    lines = [f"{EMOJI[t.severity]} *[{t.severity}] {t.category.replace('_', ' ')}*: {event.title}", t.summary,
             f"Team: *{t.team}* · confidence {t.confidence:.0%}" + (" · needs human review" if t.needs_human else "")]
    if t.runbook:
        lines.append(f"Runbook: {t.runbook}")
    lines += [f"_policy: {note}_" for note in t.policy_notes]
    return {"text": "\n".join(lines)}


def fmt_pagerduty(event: Event, t: Triage, dest: Destination) -> dict:
    return {"event_action": "trigger", "dedup_key": event.fingerprint,
            "payload": {"summary": f"[{t.severity}] {event.title}"[:1024], "source": event.service or event.source,
                        "severity": PD_SEVERITY[t.severity],
                        "custom_details": {"category": t.category, "team": t.team, "summary": t.summary,
                                           "runbook": t.runbook}}}


def fmt_generic(event: Event, t: Triage, dest: Destination) -> dict:
    return {"event_id": event.id, "source": event.source, "service": event.service, "title": event.title,
            **t.model_dump(), "fingerprint": event.fingerprint}


FORMATTERS: dict[str, Callable[[Event, Triage, Destination], dict]] = {
    "slack": fmt_slack, "pagerduty": fmt_pagerduty, "generic": fmt_generic,
}


# ------------------------------------------------------------------ config
@dataclass
class Destination:
    name: str
    format: str
    url: str = ""
    options: dict = field(default_factory=dict)

    @property
    def configured(self) -> bool:
        return bool(self.url) and (self.format != "pagerduty" or bool(self.options.get("routing_key")))


@dataclass
class Route:
    name: str
    when: dict
    send: list[str]
    digest: bool = False

    def matches(self, t: Triage) -> bool:
        w = self.when
        return ((("severity" not in w) or t.severity in w["severity"])
                and (("category" not in w) or t.category in w["category"])
                and (("needs_human" not in w) or t.needs_human == w["needs_human"]))


@dataclass
class RouteConfig:
    destinations: dict[str, Destination]
    routes: list[Route]

    @classmethod
    def load(cls, path: str | Path) -> RouteConfig:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        destinations = {}
        for name, spec in (data.get("destinations") or {}).items():
            spec = dict(spec)
            fmt = spec.pop("format", "generic")
            if fmt not in FORMATTERS:
                raise ValueError(f"destination '{name}': unknown format '{fmt}'")
            url = _expand(spec.pop("url", ""))
            destinations[name] = Destination(name, fmt, url, {k: _expand(v) for k, v in spec.items()})
        routes = []
        for spec in data.get("routes") or []:
            unknown = set(spec.get("when") or {}) - KNOWN_CONDITIONS
            if unknown:
                raise ValueError(f"route '{spec.get('name')}': unknown condition(s) {sorted(unknown)}")
            for dest in spec["send"]:
                if dest not in destinations:
                    raise ValueError(f"route '{spec['name']}' sends to unknown destination '{dest}'")
                if spec.get("digest") and destinations[dest].format == "pagerduty":
                    raise ValueError(f"route '{spec['name']}': a digest cannot go to a pager")
            routes.append(Route(spec["name"], spec.get("when") or {}, list(spec["send"]), bool(spec.get("digest"))))
        return cls(destinations, routes)


# ------------------------------------------------------------------ delivery
@dataclass
class DeliveryResult:
    status: str   # delivered | failed | dry_run | unconfigured
    attempts: int = 0
    code: int | None = None
    error: str | None = None


class Deliverer:
    def __init__(self, client: httpx.Client | None = None, dry_run: bool = False, max_attempts: int = 3,
                 base_delay: float = 0.5, sleep: Callable[[float], None] = time.sleep):
        self.client = client or httpx.Client(timeout=10)
        self.dry_run, self.max_attempts, self.base_delay, self.sleep = dry_run, max_attempts, base_delay, sleep

    def send(self, dest: Destination, payload: dict) -> DeliveryResult:
        if self.dry_run:
            return DeliveryResult("dry_run")
        if not dest.configured:
            return DeliveryResult("unconfigured", error="no URL (or routing key) configured")
        body = {**payload, "routing_key": dest.options["routing_key"]} if dest.format == "pagerduty" else payload
        code, error = None, None
        for attempt in range(1, self.max_attempts + 1):
            try:
                response = self.client.post(dest.url, json=body)
            except httpx.TransportError as exc:
                code, error = None, f"{type(exc).__name__}: {exc}"[:200]
            else:
                code = response.status_code
                if 200 <= code < 300:
                    return DeliveryResult("delivered", attempt, code)
                error = f"HTTP {code}"
                if code != 429 and code < 500:
                    return DeliveryResult("failed", attempt, code, error)   # a 4xx will not fix itself: do not retry
            if attempt < self.max_attempts:
                self.sleep(self.base_delay * 2 ** (attempt - 1))
        return DeliveryResult("failed", self.max_attempts, code, error)


class Router:
    def __init__(self, config: RouteConfig, store: Store, deliverer: Deliverer):
        self.config, self.store, self.deliverer = config, store, deliverer

    def dispatch(self, event: Event, triage: Triage) -> list[dict]:
        out, sent = [], set()
        for route in self.config.routes:
            if not route.matches(triage):
                continue
            for name in route.send:
                if name in sent:   # two routes naming the same destination must not double-notify
                    continue
                sent.add(name)
                dest = self.config.destinations[name]
                payload = FORMATTERS[dest.format](event, triage, dest)
                if route.digest:
                    result = DeliveryResult("queued")
                else:
                    result = self.deliverer.send(dest, payload)
                self.store.add_delivery(event.id, route.name, name, result.status, result.attempts, result.code,
                                        result.error, payload)
                out.append({"route": route.name, "destination": name, "status": result.status, "attempts": result.attempts})
        return out

    def retry_failed(self) -> dict:
        retried = delivered = 0
        for row in self.store.deliveries("failed"):
            dest = self.config.destinations.get(row["destination"])
            if dest is None:
                continue
            retried += 1
            result = self.deliverer.send(dest, row["payload"])
            self.store.update_delivery(row["id"], result.status, result.attempts, result.code, result.error)
            delivered += result.status == "delivered"
        return {"retried": retried, "delivered": delivered}

    def flush_digest(self) -> dict:
        queued = self.store.deliveries("queued")
        by_dest: dict[str, list[dict]] = {}
        for row in queued:
            by_dest.setdefault(row["destination"], []).append(row)
        sent = 0
        for name, rows in by_dest.items():
            dest = self.config.destinations[name]
            if dest.format == "slack":
                lines = [f"📋 *Digest: {len(rows)} low-priority item(s)*"]
                lines += [f"• {r['payload']['text'].splitlines()[0]}" for r in rows]
                payload = {"text": "\n".join(lines)}
            else:
                payload = {"digest": [r["payload"] for r in rows]}
            result = self.deliverer.send(dest, payload)
            for row in rows:
                self.store.update_delivery(row["id"], result.status, result.attempts, result.code, result.error)
            sent += len(rows) if result.status in {"delivered", "dry_run"} else 0
        return {"destinations": len(by_dest), "items": len(queued), "sent": sent}
