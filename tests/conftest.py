from pathlib import Path

import httpx
import pytest

from ops_triage.catalog import Catalog
from ops_triage.llm import HeuristicTriager, LLMResponse
from ops_triage.pipeline import Pipeline
from ops_triage.router import Deliverer, RouteConfig, Router
from ops_triage.store import Store

CONFIG = Path(__file__).resolve().parents[1] / "config"
URLS = {"PAGERDUTY_URL": "https://pd.test/enqueue", "PAGERDUTY_ROUTING_KEY": "rk-super-secret",
        "SLACK_INCIDENTS_URL": "https://hooks.test/incidents", "SLACK_TRIAGE_URL": "https://hooks.test/triage",
        "SLACK_DIGEST_URL": "https://hooks.test/digest", "TICKET_WEBHOOK_URL": "https://hooks.test/tickets"}


@pytest.fixture
def catalog():
    return Catalog.load(CONFIG / "catalog.yaml")


@pytest.fixture
def route_config(monkeypatch):
    for key, value in URLS.items():
        monkeypatch.setenv(key, value)
    return RouteConfig.load(CONFIG / "routes.yaml")


class Recorder:
    """Stands in for the internet: records every webhook and answers with a scripted status code."""

    def __init__(self):
        self.requests, self.script = [], []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        code = self.script.pop(0) if self.script else 200
        if isinstance(code, Exception):
            raise code
        return httpx.Response(code, json={"ok": code < 300})

    def urls(self):
        return [str(r.url) for r in self.requests]


@pytest.fixture
def recorder():
    return Recorder()


@pytest.fixture
def make_pipeline(catalog, route_config, recorder):
    def factory(llm=None, dry_run=False, **kwargs) -> Pipeline:
        store = Store(":memory:")
        client = httpx.Client(transport=httpx.MockTransport(recorder.handler))
        deliverer = Deliverer(client, dry_run=dry_run, base_delay=0.01, sleep=lambda s: recorder.sleeps.append(s))
        return Pipeline(store, llm or HeuristicTriager(), catalog, Router(route_config, store, deliverer), **kwargs)

    recorder.sleeps = []
    return factory


class StubLLM:
    """Replays scripted model replies, so tests can simulate a misbehaving or hijacked model."""

    def __init__(self, *replies):
        self.replies, self.calls = list(replies), 0

    def chat(self, messages, tools):
        self.calls += 1
        reply = self.replies.pop(0) if self.replies else self.last
        self.last = reply
        if isinstance(reply, Exception):
            raise reply
        return reply if isinstance(reply, LLMResponse) else LLMResponse(content=reply)
