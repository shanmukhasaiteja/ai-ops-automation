"""Read-only tools the triager can call to enrich an event. None of them can change anything."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .catalog import Catalog
from .models import CATEGORIES
from .store import Store


class ToolError(Exception):
    pass


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    properties: dict[str, dict]
    func: Callable[..., dict]

    def spec(self) -> dict:
        return {"type": "function", "function": {
            "name": self.name, "description": self.description,
            "parameters": {"type": "object", "properties": self.properties, "required": list(self.properties)}}}


class ToolRegistry:
    def __init__(self, tools: list[Tool]):
        self._tools = {t.name: t for t in tools}

    def specs(self) -> list[dict]:
        return [t.spec() for t in self._tools.values()]

    def call(self, name: str, args: dict) -> dict:
        tool = self._tools.get(name)
        if tool is None:
            raise ToolError(f"unknown tool '{name}'")
        if not isinstance(args, dict) or set(args) != set(tool.properties):
            raise ToolError(f"{name} expects exactly these arguments: {sorted(tool.properties)}")
        if not all(isinstance(v, str) for v in args.values()):
            raise ToolError(f"{name} arguments must be strings")
        return tool.func(**args)


def build_tools(catalog: Catalog, store: Store) -> ToolRegistry:
    def get_service_info(service: str) -> dict:
        info = catalog.services.get(service)
        return {"service": service, "known": True, **{k: info[k] for k in ("team", "tier") if k in info}} if info \
            else {"service": service, "known": False}

    def find_similar_incidents(title: str) -> dict:
        return {"matches": store.similar(title[:300])}

    def get_runbook(category: str) -> dict:
        if category not in CATEGORIES:
            raise ToolError(f"category must be one of {list(CATEGORIES)}")
        return {"category": category, "runbook": catalog.runbooks.get(category)}

    def get_on_call(team: str) -> dict:
        info = catalog.teams.get(team)
        if not info:
            return {"team": team, "known": False}
        return {"team": team, "known": True, "on_call": info.get("on_call"), "channel": info.get("channel")}

    s = {"type": "string"}
    return ToolRegistry([
        Tool("get_service_info", "Look up the owning team and criticality tier of a service.",
             {"service": s}, get_service_info),
        Tool("find_similar_incidents", "Find past incidents with a similar title and how they were triaged.",
             {"title": s}, find_similar_incidents),
        Tool("get_runbook", "Get the runbook URL for an incident category.", {"category": s}, get_runbook),
        Tool("get_on_call", "Get the on-call contact and channel for a team.", {"team": s}, get_on_call),
    ])
