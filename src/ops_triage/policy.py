"""Deterministic guardrails applied after the model: the AI proposes, these rules dispose.

The model reads attacker-influenced text, so nothing it says is allowed to quietly
suppress or downgrade something important.
"""
from __future__ import annotations

import re

from .catalog import Catalog
from .models import Event, Triage, rank, severity_for

_LINKS = re.compile(r"\[([^\]]*)\]\([^)]*\)|https?://\S+|www\.\S+", re.I)


def strip_links(text: str) -> str:
    """LLM summaries get posted into chat tools, so never let a link (a data-exfil vector) through."""
    return _LINKS.sub("[link removed]", text)


def apply_policy(event: Event, triage: Triage, catalog: Catalog, confidence_threshold: float = 0.6) -> Triage:
    notes = list(triage.policy_notes)
    sev = rank(triage.severity)
    needs_human = triage.needs_human
    category = triage.category

    # 1. The model may not calm a source-reported alert down by more than one level.
    if event.reported_severity:
        floor = min(4, rank(event.reported_severity) + 1)
        if sev > floor:
            notes.append(f"severity raised {triage.severity} -> P{floor}: the source reported {event.reported_severity}")
            sev = floor

    # 2. Security issues are never below P2.
    if category == "security" and sev > 2:
        notes.append(f"severity raised {severity_for(sev)} -> P2: security findings have a P2 floor")
        sev = 2

    # 3. Never silently suppress something the source flagged as P1/P2.
    if category == "noise" and event.reported_severity and rank(event.reported_severity) <= 2:
        needs_human = True
        notes.append(f"classified as noise but the source reported {event.reported_severity}: kept visible for review")

    # 4. Uncertainty goes to a person.
    if category == "unclassified" and not needs_human:
        needs_human = True
        notes.append("could not classify automatically")
    if triage.confidence < confidence_threshold and not needs_human:
        needs_human = True
        notes.append(f"confidence {triage.confidence:.2f} is below the {confidence_threshold:.2f} threshold")

    # 5. The model may only pick a team that exists.
    team = triage.team
    if team not in catalog.teams:
        replacement = catalog.owner_of(event.service) or "triage-desk"
        notes.append(f"unknown team '{team}' replaced with '{replacement}'")
        team = replacement

    return triage.model_copy(update={
        "severity": severity_for(sev),
        "needs_human": needs_human,
        "team": team,
        "summary": strip_links(triage.summary),
        "reasoning": strip_links(triage.reasoning),
        "runbook": catalog.runbook_for(category, event.service),   # URLs come from the catalog, never from the model
        "policy_notes": notes,
    })
