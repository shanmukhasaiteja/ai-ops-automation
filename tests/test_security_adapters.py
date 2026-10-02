import pytest

from ops_triage.adapters import PayloadError, adapt, from_alertmanager, from_github
from ops_triage.security import redact, sign, verify_signature

SECRET = b"s3cret"


def test_signature_round_trip_and_tampering():
    body = b'{"a": 1}'
    header = sign(SECRET, body)
    assert verify_signature(SECRET, body, header)
    assert not verify_signature(SECRET, b'{"a": 2}', header)
    assert not verify_signature(b"other", body, header)


@pytest.mark.parametrize("header", [None, "", "deadbeef", "md5=abc", "sha256="])
def test_malformed_signature_headers_are_rejected(header):
    assert not verify_signature(SECRET, b"x", header)


def test_redaction_masks_secrets_and_pii_and_reports_what_it_found():
    text = ("mail jane.doe@example.com key AKIAIOSFODNN7EXAMPLE token ghp_abcdefghijklmnopqrstuv "
            "password=hunter2 ssn 123-45-6789 card 4111 1111 1111 1111")
    clean, kinds = redact(text)
    for leaked in ("jane.doe", "AKIAIOSFODNN7EXAMPLE", "ghp_abcdef", "hunter2", "123-45-6789", "4111"):
        assert leaked not in clean
    assert set(kinds) == {"email", "aws_key", "token", "secret", "ssn", "card"}


def test_card_detection_uses_luhn_so_ordinary_numbers_survive():
    clean, kinds = redact("order 1234567890123 timestamp 1727800000000")
    assert "1234567890123" in clean and "card" not in kinds


def test_ip_redaction_is_opt_in():
    assert redact("from 203.0.113.50")[0] == "from 203.0.113.50"
    assert redact("from 203.0.113.50", ips=True)[0] == "from [IP]"


def test_alertmanager_only_firing_alerts_become_events():
    payload = {"alerts": [
        {"status": "firing", "labels": {"alertname": "X", "severity": "critical", "service": "checkout"},
         "annotations": {"summary": "Boom", "description": "details"}},
        {"status": "resolved", "labels": {"alertname": "Y"}, "annotations": {}}]}
    events = from_alertmanager(payload)
    assert len(events) == 1 and events[0].title == "Boom" and events[0].service == "checkout"
    assert events[0].reported_severity == "P1"


def test_github_only_opened_issues_and_severity_labels():
    issue = {"title": "Broken", "body": "b", "labels": [{"name": "p2"}]}
    events = from_github({"action": "opened", "issue": issue, "repository": {"full_name": "acme/web-app"}})
    assert events[0].service == "web-app" and events[0].reported_severity == "P2"
    assert from_github({"action": "closed", "issue": issue}) == []


def test_generic_adapter_maps_severity_words():
    assert adapt("generic", {"title": "t", "severity": "high"})[0].reported_severity == "P2"
    assert adapt("generic", {"title": "t"})[0].reported_severity is None


@pytest.mark.parametrize("source,payload", [("generic", {"body": "no title"}), ("alertmanager", {"alerts": "nope"}),
                                            ("github", {"action": "opened"}), ("generic", ["not", "a", "dict"]),
                                            ("github", {"action": "opened", "issue": {"title": ""}})])
def test_bad_payloads_raise_payload_error(source, payload):
    with pytest.raises(PayloadError):
        adapt(source, payload)


def test_same_alert_with_different_numbers_has_the_same_fingerprint():
    a, b = adapt("generic", {"title": "5xx rate 12%"})[0], adapt("generic", {"title": "5xx rate 14%"})[0]
    assert a.fingerprint == b.fingerprint
    assert a.fingerprint != adapt("generic", {"title": "disk full"})[0].fingerprint
