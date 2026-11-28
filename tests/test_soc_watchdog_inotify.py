from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import soc_watchdog as watchdog


def usage(percent):
    return {
        "total": int(percent * 10), "limit": 1000, "percent": percent,
        "top_pid": "123", "top_watches": int(percent * 9),
        "top_command": "/usr/libexec/uresourced --user",
    }


def scenario(monkeypatch, percent):
    sent = []
    monkeypatch.setattr(watchdog, "collect_inotify_usage", lambda: usage(percent))
    monkeypatch.setattr(watchdog, "send_inotify_gelf",
                        lambda *args: sent.append(args))
    return sent


def test_normal_usage_does_not_create_alert(monkeypatch):
    sent = scenario(monkeypatch, 6.7)
    state = {}
    result = watchdog.check_inotify(state)
    assert result["status"] == "OK"
    assert result["delivery"] == "not-needed"
    assert sent == []


def test_warning_is_sent_once_and_state_is_retained(monkeypatch):
    sent = scenario(monkeypatch, 72)
    state = {}
    first = watchdog.check_inotify(state)
    second = watchdog.check_inotify(state)
    assert first["status"] == second["status"] == "WARNING"
    assert first["delivery"] == "sent"
    assert second["delivery"] == "not-needed"
    assert len(sent) == 1
    assert sent[0][1:] == ("PROBLEM", "WARNING", usage(72))
    assert state["inotify"]["status"] == "WARNING"


def test_escalation_hysteresis_and_recovery_use_one_event(monkeypatch):
    sent = scenario(monkeypatch, 72)
    state = {}
    watchdog.check_inotify(state)
    event_id = state["inotify"]["event_id"]

    monkeypatch.setattr(watchdog, "collect_inotify_usage", lambda: usage(90))
    assert watchdog.check_inotify(state)["status"] == "CRITICAL"
    monkeypatch.setattr(watchdog, "collect_inotify_usage", lambda: usage(65))
    assert watchdog.check_inotify(state)["status"] == "CRITICAL"
    monkeypatch.setattr(watchdog, "collect_inotify_usage", lambda: usage(50))
    assert watchdog.check_inotify(state)["status"] == "OK"

    assert [call[1] for call in sent] == ["PROBLEM", "PROBLEM", "RESOLVED"]
    assert [call[2] for call in sent] == ["WARNING", "CRITICAL", "OK"]
    assert all(call[0] == event_id for call in sent)


def test_delivery_failure_is_retried_without_losing_active_state(monkeypatch):
    monkeypatch.setattr(watchdog, "collect_inotify_usage", lambda: usage(90))

    def fail(*args):
        raise RuntimeError("Graylog unavailable")

    monkeypatch.setattr(watchdog, "send_inotify_gelf", fail)
    state = {"inotify": {"status": "WARNING", "event_id": "inotify-test"}}
    failed = watchdog.check_inotify(state)
    assert failed["status"] == "CRITICAL"
    assert failed["delivery"].startswith("error:")
    assert state["inotify"]["status"] == "WARNING"

    sent = []
    monkeypatch.setattr(watchdog, "send_inotify_gelf", lambda *args: sent.append(args))
    assert watchdog.check_inotify(state)["delivery"] == "sent"
    assert sent[0][0] == "inotify-test"
    assert state["inotify"]["status"] == "CRITICAL"


def test_invalid_thresholds_fail_explicitly(monkeypatch):
    scenario(monkeypatch, 50)
    monkeypatch.setenv("INOTIFY_RECOVER_PERCENT", "80")
    with pytest.raises(ValueError, match="INOTIFY_RECOVER_PERCENT"):
        watchdog.check_inotify({})


def test_gelf_payload_has_metrics_and_runbook(monkeypatch):
    payloads = []
    monkeypatch.setattr(watchdog, "send_gelf_payload", payloads.append)
    watchdog.send_inotify_gelf("inotify-test", "PROBLEM", "CRITICAL", usage(90))
    payload = payloads[0]
    assert payload["_zabbix_event_id"] == "inotify-test"
    assert payload["_zabbix_event_status"] == "PROBLEM"
    assert payload["_zabbix_nseverity"] == 4
    assert payload["_inotify_watches"] == 900
    assert payload["_inotify_limit"] == 1000
    assert payload["_inotify_percent"] == 90
    assert "art-monitoring-restore" in payload["_zabbix_url"]
    assert "uresourced" in payload["_inotify_top_command"]
