"""FastAPI service: signed webhooks in, triaged and routed notifications out."""
from __future__ import annotations

import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool

from .adapters import ADAPTERS, PayloadError, adapt
from .catalog import Catalog
from .llm import HeuristicTriager, OpenAICompatibleClient
from .pipeline import Pipeline
from .router import Deliverer, RouteConfig, Router
from .security import verify_signature
from .store import Store

MAX_BODY_BYTES = 256 * 1024


@dataclass
class Settings:
    db_path: str = "ops.db"
    config_dir: str = "config"
    webhook_secret: str = ""
    admin_token: str = ""
    llm: str = "heuristic"          # heuristic | openai
    dry_run: bool = True            # safe default: record what would be sent, send nothing
    dedupe_window: int = 900
    confidence_threshold: float = 0.6

    @classmethod
    def from_env(cls) -> Settings:
        env = os.environ.get
        return cls(db_path=env("OPS_DB", "ops.db"), config_dir=env("OPS_CONFIG_DIR", "config"),
                   webhook_secret=env("WEBHOOK_SECRET", ""), admin_token=env("ADMIN_TOKEN", ""),
                   llm=env("OPS_LLM", "heuristic"), dry_run=env("OPS_DRY_RUN", "1") not in {"0", "false", "no"},
                   dedupe_window=int(env("OPS_DEDUPE_WINDOW", "900")),
                   confidence_threshold=float(env("OPS_CONFIDENCE_THRESHOLD", "0.6")))


def build_pipeline(settings: Settings) -> Pipeline:
    config = Path(settings.config_dir)
    store = Store(settings.db_path)
    catalog = Catalog.load(config / "catalog.yaml")
    router = Router(RouteConfig.load(config / "routes.yaml"), store, Deliverer(dry_run=settings.dry_run))
    llm = OpenAICompatibleClient() if settings.llm == "openai" else HeuristicTriager()
    return Pipeline(store, llm, catalog, router, settings.dedupe_window, settings.confidence_threshold)


def create_app(settings: Settings | None = None, pipeline: Pipeline | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    pipeline = pipeline or build_pipeline(settings)
    app = FastAPI(title="ai-ops-automation", version="0.1.0")

    def require_admin(request: Request) -> None:
        if settings.admin_token and not hmac.compare_digest(request.headers.get("X-Admin-Token", ""), settings.admin_token):
            raise HTTPException(401, "admin token required")

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok", "llm": settings.llm, "dry_run": settings.dry_run}

    @app.post("/webhooks/{source}", status_code=202)
    async def webhook(source: str, request: Request) -> dict:
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
            raise HTTPException(413, "payload too large")
        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            raise HTTPException(413, "payload too large")
        if settings.webhook_secret and not verify_signature(settings.webhook_secret.encode(), body,
                                                            request.headers.get("X-Signature-256")):
            raise HTTPException(401, "invalid or missing signature")
        if source not in ADAPTERS:
            raise HTTPException(404, f"unknown source '{source}', expected one of {sorted(ADAPTERS)}")
        try:
            payload = json.loads(body)
        except ValueError:
            raise HTTPException(400, "body is not valid JSON") from None
        try:
            events = adapt(source, payload)
        except PayloadError as exc:
            raise HTTPException(422, str(exc)) from None
        outcomes = [await run_in_threadpool(pipeline.process, event) for event in events]
        return {"received": len(events), "results": [o.to_dict() for o in outcomes]}

    @app.get("/events", dependencies=[Depends(require_admin)])
    def events(limit: int = Query(50, ge=1, le=500)) -> list[dict]:
        return pipeline.store.recent(limit)

    @app.get("/metrics", dependencies=[Depends(require_admin)])
    def metrics() -> dict:
        return pipeline.store.stats()

    @app.post("/digest/flush", dependencies=[Depends(require_admin)])
    def flush_digest() -> dict:
        return pipeline.router.flush_digest()

    @app.post("/deliveries/retry", dependencies=[Depends(require_admin)])
    def retry_deliveries() -> dict:
        return pipeline.router.retry_failed()

    return app
