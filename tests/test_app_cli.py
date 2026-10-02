import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ops_triage.app import MAX_BODY_BYTES, Settings, create_app
from ops_triage.cli import main
from ops_triage.security import sign

SECRET = "whsec_test"
ADMIN = "admin-token"
ALERT = {"title": "Checkout 5xx rate above 5%", "body": "5xx errors, all users affected", "service": "checkout",
         "severity": "critical"}


@pytest.fixture
def client(make_pipeline):
    settings = Settings(webhook_secret=SECRET, admin_token=ADMIN, dry_run=False)
    return TestClient(create_app(settings, make_pipeline()))


def post(client, path, payload, secret=SECRET, raw=None):
    body = raw if raw is not None else json.dumps(payload).encode()
    headers = {"X-Signature-256": sign(secret.encode(), body)} if secret else {}
    return client.post(path, content=body, headers={**headers, "Content-Type": "application/json"})


def test_a_signed_webhook_is_accepted_triaged_and_routed(client, recorder):
    response = post(client, "/webhooks/generic", ALERT)
    assert response.status_code == 202
    result = response.json()["results"][0]
    assert result["triage"]["severity"] == "P1" and result["triage"]["team"] == "payments"
    assert {d["destination"] for d in result["deliveries"]} == {"pagerduty", "slack-incidents"}
    assert len(recorder.requests) == 2


@pytest.mark.parametrize("secret", ["wrong-secret", None])
def test_unsigned_or_wrongly_signed_webhooks_are_rejected_before_any_work(client, recorder, secret):
    assert post(client, "/webhooks/generic", ALERT, secret=secret).status_code == 401
    assert recorder.requests == [] and client.get("/metrics", headers={"X-Admin-Token": ADMIN}).json()["events"] == 0


def test_signature_must_match_the_exact_bytes_sent(client):
    body = json.dumps(ALERT).encode()
    headers = {"X-Signature-256": sign(SECRET.encode(), body)}
    response = client.post("/webhooks/generic", content=body + b" ", headers=headers)
    assert response.status_code == 401


def test_bad_requests_get_precise_errors(client):
    assert post(client, "/webhooks/nope", ALERT).status_code == 404
    assert post(client, "/webhooks/generic", None, raw=b"{not json").status_code == 400
    assert post(client, "/webhooks/generic", {"body": "no title"}).status_code == 422
    assert post(client, "/webhooks/generic", ["a list"]).status_code == 422


def test_oversized_payloads_are_refused(client):
    huge = b'{"title": "' + b"x" * (MAX_BODY_BYTES + 10) + b'"}'
    assert post(client, "/webhooks/generic", None, raw=huge).status_code == 413


def test_resolved_alerts_are_acknowledged_but_do_nothing(client, recorder):
    payload = {"alerts": [{"status": "resolved", "labels": {"alertname": "X"}, "annotations": {}}]}
    response = post(client, "/webhooks/alertmanager", payload)
    assert response.status_code == 202 and response.json() == {"received": 0, "results": []}


def test_a_duplicate_is_reported_as_such(client):
    post(client, "/webhooks/generic", ALERT)
    again = post(client, "/webhooks/generic", {**ALERT, "title": "Checkout 5xx rate above 7%"})
    assert again.json()["results"][0]["status"] == "duplicate"


def test_admin_endpoints_require_the_token(client):
    for method, path in (("get", "/events"), ("get", "/metrics"), ("post", "/digest/flush"), ("post", "/deliveries/retry")):
        assert getattr(client, method)(path).status_code == 401
        assert getattr(client, method)(path, headers={"X-Admin-Token": "wrong"}).status_code == 401
    assert client.get("/healthz").status_code == 200   # health stays open for load balancers


def test_metrics_events_digest_and_retry_endpoints(client):
    post(client, "/webhooks/generic", ALERT)
    post(client, "/webhooks/generic", {"title": "Request access", "body": "please grant access, new joiner"})
    admin = {"X-Admin-Token": ADMIN}
    metrics = client.get("/metrics", headers=admin).json()
    assert metrics["events"] == 2 and metrics["by_severity"] == {"P1": 1, "P4": 1}
    assert len(client.get("/events?limit=1", headers=admin).json()) == 1
    assert client.post("/digest/flush", headers=admin).json()["items"] == 1
    assert client.post("/deliveries/retry", headers=admin).json() == {"retried": 0, "delivered": 0}


def test_without_a_configured_secret_the_service_runs_open_for_local_development(make_pipeline):
    open_client = TestClient(create_app(Settings(webhook_secret="", dry_run=False), make_pipeline()))
    assert post(open_client, "/webhooks/generic", ALERT, secret=None).status_code == 202


# ------------------------------------------------------------------ CLI
SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "events.jsonl"
CONFIG = SAMPLES.parents[1] / "config"


def test_replay_runs_the_sample_events_end_to_end(capsys):
    assert main(["replay", "--events", str(SAMPLES), "--config-dir", str(CONFIG)]) == 0
    out = capsys.readouterr().out
    assert "11 triaged · 1 duplicates suppressed · 1 skipped · 2 need a human" in out
    assert "redacted before the LLM saw it" in out and "kept visible for review" in out


def test_sign_command_matches_the_library(tmp_path, capsys):
    f = tmp_path / "body.json"
    f.write_bytes(b'{"title": "x"}')
    assert main(["sign", str(f), "--secret", "abc"]) == 0
    assert capsys.readouterr().out.strip() == sign(b"abc", b'{"title": "x"}')


def test_missing_events_file_is_a_clean_error(capsys):
    assert main(["replay", "--events", "/nope.jsonl"]) == 2
    assert "error:" in capsys.readouterr().err
