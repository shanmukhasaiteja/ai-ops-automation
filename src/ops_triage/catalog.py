"""Who owns what: services, teams and runbooks. Loaded from config/catalog.yaml."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Catalog:
    services: dict[str, dict] = field(default_factory=dict)
    teams: dict[str, dict] = field(default_factory=dict)
    runbooks: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> Catalog:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls(data.get("services") or {}, data.get("teams") or {}, data.get("runbooks") or {})

    def owner_of(self, service: str | None) -> str | None:
        return (self.services.get(service or "") or {}).get("team")

    def runbook_for(self, category: str, service: str | None = None) -> str | None:
        return (self.services.get(service or "") or {}).get("runbook") or self.runbooks.get(category)
