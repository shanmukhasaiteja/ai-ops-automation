"""LLM backends for the triager.

* ``OpenAICompatibleClient``: real tool-calling against any OpenAI-compatible API.
* ``HeuristicTriager``: a deterministic, keyword-based stand-in that needs no API key. It is NOT an LLM; it lets the
  whole pipeline (guardrails, policy, routing) run and be tested offline and in CI.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Protocol

import httpx

from .models import rank, severity_for


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict


@dataclass
class LLMResponse:
    content: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)


class LLMClient(Protocol):
    def chat(self, messages: list[dict], tools: list[dict]) -> LLMResponse: ...


class LLMError(RuntimeError):
    pass


class OpenAICompatibleClient:
    def __init__(self, model: str | None = None, base_url: str | None = None, api_key: str | None = None):
        self.model = model or os.getenv("LLM_MODEL", "gpt-4o-mini")
        self.base_url = (base_url or os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.api_key = api_key if api_key is not None else os.getenv("LLM_API_KEY", "")
        if not self.api_key and "localhost" not in self.base_url and "127.0.0.1" not in self.base_url:
            raise LLMError("LLM_API_KEY is not set (see .env.example), or run with OPS_LLM=heuristic")

    def chat(self, messages: list[dict], tools: list[dict]) -> LLMResponse:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        try:
            response = httpx.post(f"{self.base_url}/chat/completions", headers=headers, timeout=60,
                                  json={"model": self.model, "messages": messages, "tools": tools, "temperature": 0})
        except httpx.HTTPError as exc:
            raise LLMError(f"request failed: {exc}") from exc
        if response.status_code != 200:
            raise LLMError(f"HTTP {response.status_code}: {response.text[:200]}")
        try:
            message = response.json()["choices"][0]["message"]
        except (KeyError, IndexError, ValueError) as exc:
            raise LLMError("unexpected response shape") from exc
        calls = []
        for raw in message.get("tool_calls") or []:
            try:
                args = json.loads(raw["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            calls.append(ToolCall(raw["id"], raw["function"]["name"], args))
        return LLMResponse(message.get("content"), calls)


# ------------------------------------------------------------------ offline stand-in
KEYWORDS: dict[str, tuple[str, ...]] = {
    "security": ("unauthorized", "brute force", "failed login", "suspicious", "malware", "exfiltrat", "cve-", "vulnerab",
                 "phishing", "credential", "privilege escalation", "port scan", "sql injection", "leaked", "leak"),
    "infrastructure": ("cpu", "memory", "disk", "latency", "5xx", "timeout", "crashloop", "oomkilled", "node ", "outage",
                       "unreachable", "saturation", "error rate", "down"),
    "data_quality": ("null rate", "schema", "stale", "freshness", "duplicate rows", "row count", "pipeline", "dbt",
                     "airflow", "backfill"),
    "access_request": ("request access", "access request", "please grant", "needs permission", "onboarding", "vpn access",
                       "new joiner"),
    "billing": ("invoice", "refund", "chargeback", "billing", "overcharged", "charged twice", "subscription"),
    "bug": ("bug", "regression", "unexpected", "crash", "stack trace", "exception", "typo", "broken"),
    "noise": ("test alert", "[test]", "this is a test", "heartbeat", "dry run", "ignore this"),
}
PRIORITY = ("security", "infrastructure", "data_quality", "access_request", "billing", "bug", "noise")
DEFAULT_SEVERITY = {"security": "P2", "infrastructure": "P3", "data_quality": "P3", "access_request": "P4",
                    "billing": "P4", "bug": "P3", "noise": "P4", "unclassified": "P3"}
DEFAULT_TEAM = {"security": "security", "infrastructure": "platform", "data_quality": "data-platform",
                "access_request": "it-helpdesk", "billing": "finance-ops", "bug": "engineering",
                "noise": "triage-desk", "unclassified": "triage-desk"}
# these are handled by a specialist team no matter which service they mention
CATEGORY_OWNED = {"security", "access_request", "billing"}
ESCALATORS = ("outage", "all users", "data loss", "breach", "production down", "complete failure", "exposed")
_EVENT_RE = re.compile(r"<event>\s*(.*?)\s*</event>", re.S)


def _history(messages: list[dict]) -> dict[str, list[dict]]:
    results = {m["tool_call_id"]: json.loads(m["content"]) for m in messages if m.get("role") == "tool"}
    out: dict[str, list[dict]] = {}
    for m in messages:
        for call in m.get("tool_calls") or []:
            out.setdefault(call["function"]["name"], []).append(results.get(call["id"], {}))
    return out


class HeuristicTriager:
    def chat(self, messages: list[dict], tools: list[dict]) -> LLMResponse:
        match = _EVENT_RE.search(next(m["content"] for m in reversed(messages) if m["role"] == "user"))
        event = json.loads(match.group(1).replace("<\\/event>", "</event>")) if match else {}
        text = f"{event.get('title', '')} {event.get('body', '')}".lower()
        scores = {c: sum(text.count(k) for k in KEYWORDS[c]) for c in PRIORITY}
        category = max(PRIORITY, key=lambda c: (scores[c], -PRIORITY.index(c)))
        hits = scores[category]
        if hits == 0:
            category = "unclassified"

        done = _history(messages)
        n = len(messages)
        if event.get("service") and "get_service_info" not in done:
            return self._call(n, "get_service_info", {"service": event["service"]})
        if "find_similar_incidents" not in done:
            return self._call(n, "find_similar_incidents", {"title": event.get("title", "")})
        if "get_runbook" not in done:
            return self._call(n, "get_runbook", {"category": category})

        service = (done.get("get_service_info") or [{}])[0]
        similar = (done["find_similar_incidents"][0] or {}).get("matches", [])
        confidence = 0.25 if hits == 0 else 0.4 + 0.15 * min(hits, 3)
        runner_up = sorted(scores.values(), reverse=True)[1]
        if hits and runner_up == hits:
            confidence -= 0.2
        if similar and similar[0].get("category") == category:
            confidence += 0.1

        sev = rank(DEFAULT_SEVERITY[category])
        if event.get("reported_severity"):
            sev = min(sev, rank(event["reported_severity"]))
        if any(word in text for word in ESCALATORS) and category in {"infrastructure", "security", "data_quality"}:
            sev = 1
        if service.get("tier") == 1 and category == "infrastructure":
            sev = max(1, sev - 1)

        reason = ", ".join(k for k in KEYWORDS.get(category, ()) if k in text) or "no known keywords"
        result = {
            "category": category, "severity": severity_for(sev),
            "summary": f"{event.get('title', '')}"[:200],
            "team": DEFAULT_TEAM[category] if category in CATEGORY_OWNED else service.get("team") or DEFAULT_TEAM[category],
            "confidence": round(max(0.2, min(0.95, confidence)), 2),
            "reasoning": f"keyword match ({reason}); service tier {service.get('tier', 'unknown')}; "
                         f"{len(similar)} similar past incident(s)",
        }
        return LLMResponse(content=json.dumps(result))

    @staticmethod
    def _call(n: int, name: str, args: dict) -> LLMResponse:
        return LLMResponse(tool_calls=[ToolCall(f"call_{n}", name, args)])
