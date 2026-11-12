import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app as tb


def zabbix_event(severity=4):
    return {
        "id": "event/1",
        "message": "ZABBIX - aggregated",
        "timestamp": "2026-11-12T00:00:00Z",
        "priority": 2,
        "event_definition_id": "graylog-rule",
        "fields": {
            "zabbix_event_id": "123456",
            "zabbix_nseverity": severity,
            "zabbix_trigger_description": "HTTPS service unavailable",
            "host": "app.example.test",
            "zabbix_url": "https://zabbix.example.test/tr_events.php?eventid=123456",
            "zabbix_event_duration": "00:05:42",
        },
    }


@pytest.mark.parametrize("severity,expected", [(0, 4), (2, 4), (3, 1), (4, 5), (5, 5)])
def test_zabbix_severity_mapping(severity, expected):
    assert tb.zabbix_iris_severity({"zabbix_nseverity": severity}, 2) == expected


def test_zabbix_severity_fallback_does_not_change_graylog():
    assert tb.zabbix_iris_severity({}, 3) == 5
    assert tb.zabbix_iris_severity({"zabbix_nseverity": "invalid"}, 1) == 4
    assert tb.zabbix_iris_severity({"zabbix_nseverity": 99}, 2) == 1


def test_zabbix_ticket_title_links_and_runbook_tag(monkeypatch):
    monkeypatch.setattr(tb, "GRAYLOG", "https://graylog.example.test")
    event = zabbix_event()
    event["fields"]["zabbix_tags_json"] = json.dumps([
        {"tag": "application", "value": "IRIS"},
        {"tag": "runbook", "value": "https://homewiki.example.test/rules/app"},
    ])
    title, content, _ = tb.compose_ticket(event)
    assert title == "[Zabbix] HTTPS service unavailable — app.example.test"
    assert "🚨 Событие Zabbix" in content
    assert "🔎 Replay Search в Graylog" in content
    assert "event%2F1/replay-search" in content
    assert "https://homewiki.example.test/rules/app" in content
    assert content.count("📖 Рунбук в HomeWiki") == 1


def test_zabbix_links_reject_non_http_and_fall_back_to_runbook():
    event = zabbix_event()
    event["fields"]["zabbix_url"] = "javascript:alert(1)"
    _, content, _ = tb.compose_ticket(event)
    assert "href='javascript:" not in content
    assert "🚨 Событие Zabbix" not in content
    assert tb.ZABBIX_HOMEWIKI in content


def test_send_iris_uses_zabbix_title_and_severity(tmp_path, monkeypatch):
    monkeypatch.setattr(tb, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(tb, "IRIS", "https://iris.example.test")
    monkeypatch.setattr(tb, "IRIS_KEY", "secret")
    payloads = []
    monkeypatch.setattr(tb, "_post_iris", lambda payload: payloads.append(payload) or (True, "801"))
    event = zabbix_event(5)
    assert tb.send_iris(event) == (True, "801")
    assert tb.send_iris(event) == (True, "801")
    assert len(payloads) == 1
    assert payloads[0]["alert_title"].startswith("[Zabbix] HTTPS service unavailable")
    assert payloads[0]["alert_severity_id"] == 5


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self):
        return b"{}"


def prepare_close(tmp_path, monkeypatch):
    monkeypatch.setattr(tb, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(tb, "IRIS", "https://iris.example.test")
    monkeypatch.setattr(tb, "IRIS_KEY", "secret")
    con = tb.state_db()
    con.execute("INSERT INTO iris_dedup VALUES('zabbix:123456',801,1)")
    con.commit()
    con.close()
    event = zabbix_event()
    event["fields"]["zabbix_event_status"] = "RESOLVED"
    return event


def test_close_iris_adds_recovery_comment(tmp_path, monkeypatch):
    event = prepare_close(tmp_path, monkeypatch)
    requests = []
    monkeypatch.setattr(tb.urllib.request, "urlopen",
                        lambda req, **kwargs: requests.append(req) or FakeResponse())
    assert tb.close_iris(event) == (True, "801")
    assert [req.method for req in requests] == ["PUT", "POST"]
    assert requests[1].full_url == "https://iris.example.test/api/v2/alerts/801/comments"
    comment = json.loads(requests[1].data)["comment_text"]
    assert "123456" in comment and "00:05:42" in comment
    assert "Событие Zabbix" in comment and "Replay Search в Graylog" in comment
    assert "Рунбук в HomeWiki" in comment


def test_close_iris_succeeds_when_comment_fails(tmp_path, monkeypatch):
    event = prepare_close(tmp_path, monkeypatch)
    requests, logs = [], []
    monkeypatch.setattr(tb, "send_gelf", lambda short, **fields: logs.append(fields))

    def fake_urlopen(req, **kwargs):
        requests.append(req)
        if req.method == "POST":
            raise RuntimeError("comments unavailable")
        return FakeResponse()

    monkeypatch.setattr(tb.urllib.request, "urlopen", fake_urlopen)
    assert tb.close_iris(event) == (True, "801")
    assert len(requests) == 2
    assert logs[-1]["tb_event"] == "iris_comment_error"
    assert logs[-1]["iris_alert_id"] == 801
