import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import soc_canary as canary


def test_gelf_payload_contains_unique_id_and_canary_marker():
    payload = canary.gelf_payload("soc-canary-test-123", timestamp=123.5)
    assert payload["_soc_canary"] == "true"
    assert payload["_soc_canary_id"] == "soc-canary-test-123"
    assert "soc-canary-test-123" in payload["short_message"]
    assert payload["level"] == 6


def test_definition_is_low_and_only_uses_ticketbridge():
    definition = canary.canary_definition("notification-1")
    assert definition["priority"] == 1
    assert definition["config"]["query"] == "soc_canary:true"
    assert definition["config"]["group_by"] == ["soc_canary_id"]
    assert definition["notifications"] == [
        {"notification_id": "notification-1", "notification_parameters": None}]
    assert "mitre_tactic" not in definition["field_spec"]


def test_alert_matching_requires_exact_unique_id_in_owned_text():
    alert = {"alert_id": 10, "alert_title": "HEALTH - SOC canary",
             "alert_description": "event = soc-canary-abc"}
    assert canary.alert_has_id(alert, "soc-canary-abc")
    assert not canary.alert_has_id(alert, "soc-canary-other")
    assert not canary.alert_has_id({"alert_id": 10}, "10")


def test_close_refuses_foreign_alert():
    iris = canary.Iris("https://iris.example.test", "secret")
    iris.request = lambda *args, **kwargs: pytest.fail("API must not be called")
    with pytest.raises(RuntimeError, match="Refusing to close"):
        iris.close_own_alert({"alert_id": 99, "alert_title": "unrelated"},
                             "soc-canary-own", "comment")


def test_close_own_alert_sets_closed_and_legitimate_then_comments():
    iris = canary.Iris("https://iris.example.test", "secret")
    calls = []
    iris.request = lambda method, path, body=None: calls.append((method, path, body)) or {}
    alert_id = iris.close_own_alert(
        {"alert_id": 101, "alert_description": "SOC canary soc-canary-own"},
        "soc-canary-own", "verified")
    assert alert_id == 101
    assert calls == [
        ("PUT", "/api/v2/alerts/101",
         {"alert_status_id": 6, "alert_resolution_status_id": 6}),
        ("POST", "/api/v2/alerts/101/comments", {"comment_text": "verified"}),
    ]


def test_verified_closed_requires_both_statuses():
    iris = canary.Iris("https://iris.example.test", "secret")
    iris.request = lambda *args: {"alert_status_id": 6, "alert_resolution_status_id": 6}
    assert iris.verified_closed(1)["alert_status_id"] == 6
    iris.request = lambda *args: {"alert_status_id": 6, "alert_resolution_status_id": None}
    assert iris.verified_closed(1) is None


def test_wait_for_reports_the_failed_stage_without_real_delay():
    clock = iter([0, 0, 31])
    with pytest.raises(TimeoutError, match="Stage graylog_event timed out after 30s"):
        canary.wait_for("graylog_event", lambda: None, 30, interval=0,
                        monotonic=lambda: next(clock), sleep=lambda _: None)


def test_wait_for_retries_transient_api_error():
    calls = iter([None, {"id": "event-1"}])
    value = canary.wait_for("graylog_event", lambda: next(calls), 30, interval=0,
                            sleep=lambda _: None)
    assert value == {"id": "event-1"}


def test_state_is_private_and_success_metrics_are_sent(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setitem(sys.modules, "soc_watchdog",
                        SimpleNamespace(send_trapper=sent.append))
    state_path = tmp_path / "state.json"
    state = {"canary_id": "soc-canary-state", "stages": {}}
    metrics = canary.report_metrics(state_path, tmp_path / "history", state, True,
                                    __import__("time").monotonic())
    assert metrics["soc.canary.status"] == 1
    assert sent == [metrics]
    assert json.loads(state_path.read_text())["status"] == "ok"
    assert state_path.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "history" / "soc-canary-state.json").stat().st_mode & 0o777 == 0o600


def test_failure_uses_one_persistent_fallback_and_recovery_resolves_it(tmp_path, monkeypatch):
    fallback = []
    module = SimpleNamespace(
        send_trapper=lambda metrics: (_ for _ in ()).throw(RuntimeError("trapper down")),
        send_gelf=lambda *args: fallback.append(args))
    monkeypatch.setitem(sys.modules, "soc_watchdog", module)
    state_path = tmp_path / "state.json"
    failed = {"canary_id": "soc-canary-failed", "stages": {}, "error": "IRIS timeout"}
    canary.report_metrics(state_path, tmp_path / "history", failed, False,
                          __import__("time").monotonic())
    assert fallback[0][1] == "PROBLEM"
    event_id = json.loads(state_path.read_text())["fallback_event_id"]
    assert event_id

    module.send_trapper = lambda metrics: None
    recovered = {"canary_id": "soc-canary-recovered", "stages": {},
                 "fallback_event_id": event_id}
    canary.report_metrics(state_path, tmp_path / "history", recovered, True,
                          __import__("time").monotonic())
    assert fallback[-1][:2] == (event_id, "RESOLVED")
    assert json.loads(state_path.read_text())["fallback_event_id"] is None


def test_setup_update_uses_unwrapped_graylog_entity(tmp_path):
    existing = dict(canary.canary_definition("notification-1"), id="rule-1")

    class FakeGraylog:
        def __init__(self):
            self.persisted = existing
            self.put_body = None

        def definitions(self):
            return [existing]

        def request(self, method, path, body=None):
            if path == "/api/events/notifications?per_page=200&page=1":
                return {"notifications": [{"id": "notification-1", "title": canary.NOTIFICATION_TITLE}]}
            if path == "/api/events/notifications/notification-1":
                return {"id": "notification-1", "title": canary.NOTIFICATION_TITLE}
            if method == "PUT":
                self.put_body = body
                self.persisted = dict(body, id="rule-1")
                return self.persisted
            if path == "/api/events/definitions/rule-1":
                return self.persisted
            raise AssertionError((method, path))

    graylog = FakeGraylog()
    result = canary.setup(graylog, True, tmp_path)
    assert result["verified"] is True
    assert graylog.put_body["title"] == canary.TITLE
    assert graylog.put_body["id"] == "rule-1"
    assert "entity" not in graylog.put_body
