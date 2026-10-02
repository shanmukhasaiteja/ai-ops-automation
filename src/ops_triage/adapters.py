"""Turn each source system's webhook payload into the common Event shape."""
from __future__ import annotations

from collections.abc import Callable

from pydantic import ValidationError

from .models import Event

_ALERTMANAGER_SEVERITY = {"critical": "P1", "error": "P2", "warning": "P3", "info": "P4"}
_GENERIC_SEVERITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4",
                     "p1": "P1", "p2": "P2", "p3": "P3", "p4": "P4"}


class PayloadError(ValueError):
    """The webhook body is valid JSON but not a payload this adapter understands."""


def from_alertmanager(payload: dict) -> list[Event]:
    alerts = payload.get("alerts")
    if not isinstance(alerts, list):
        raise PayloadError("alertmanager payload needs an 'alerts' list")
    events = []
    for alert in alerts:
        if not isinstance(alert, dict) or alert.get("status", "firing") != "firing":
            continue   # resolved alerts are not new work
        labels = {str(k): str(v) for k, v in (alert.get("labels") or {}).items()}
        notes = alert.get("annotations") or {}
        events.append(Event(
            source="alertmanager",
            title=notes.get("summary") or labels.get("alertname", "alert"),
            body=notes.get("description", ""),
            service=labels.get("service") or labels.get("job"),
            reported_severity=_ALERTMANAGER_SEVERITY.get(labels.get("severity", "").lower()),
            labels=labels,
        ))
    return events


def from_github(payload: dict) -> list[Event]:
    issue = payload.get("issue")
    if not isinstance(issue, dict):
        raise PayloadError("github payload needs an 'issue' object")
    if payload.get("action") != "opened":
        return []
    repo = (payload.get("repository") or {}).get("full_name") or ""
    names = [str(label.get("name", "")) for label in issue.get("labels") or [] if isinstance(label, dict)]
    severity = next((_GENERIC_SEVERITY[n.lower()] for n in names if n.lower() in _GENERIC_SEVERITY), None)
    return [Event(
        source="github", title=issue.get("title") or "", body=issue.get("body") or "",
        service=repo.split("/")[-1] or None, reported_severity=severity,
        labels={"repo": repo, "labels": ",".join(names)},
    )]


def from_generic(payload: dict) -> list[Event]:
    if not isinstance(payload, dict) or "title" not in payload:
        raise PayloadError("generic payload needs a 'title'")
    severity = _GENERIC_SEVERITY.get(str(payload.get("severity", "")).lower())
    labels = {str(k): str(v) for k, v in (payload.get("labels") or {}).items()}
    return [Event(source=str(payload.get("source", "generic"))[:40], title=str(payload["title"]),
                  body=str(payload.get("body", "")), service=payload.get("service"),
                  reported_severity=severity, labels=labels)]


ADAPTERS: dict[str, Callable[[dict], list[Event]]] = {
    "alertmanager": from_alertmanager, "github": from_github, "generic": from_generic,
}


def adapt(source: str, payload: dict) -> list[Event]:
    if not isinstance(payload, dict):
        raise PayloadError("payload must be a JSON object")
    try:
        return ADAPTERS[source](payload)
    except ValidationError as exc:
        raise PayloadError(f"invalid {source} payload: {exc.errors()[0]['msg']}") from exc
