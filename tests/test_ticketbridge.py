import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app as tb


def test_compose_ticket_full():
    event = {"message": "TRAFFICLENS - Обращение к индикатору компрометации",
             "timestamp": "2026-11-09T12:00:00Z", "priority": 3,
             "event_definition_id": "abc123",
             "fields": {"ioc": "8.8.8.8", "ioc_type": "ip",
                        "tl_report": "https://trafficlens.example/jobs/1"}}
    name, content, urgency = tb.compose_ticket(event)
    assert name.startswith("[Graylog] TRAFFICLENS")
    assert "8.8.8.8" in content and "blockboard" in content.lower()
    assert "homewiki" in content and "abc123" in content
    assert "trafficlens.example/jobs/1" in content
    assert urgency == 5


def test_compose_ticket_no_ioc_no_blockboard():
    event = {"message": "X - тест", "timestamp": "t", "priority": 1,
             "event_definition_id": "d", "fields": {"ioc": "44d88612fea8a8f36de82e1278abb02f",
                                                    "ioc_type": "md5"}}
    name, content, urgency = tb.compose_ticket(event)
    assert "blockboard" not in content.lower()
    assert urgency == 1


def test_compose_ticket_escapes_html():
    event = {"message": "<script>alert(1)</script>", "timestamp": "t", "priority": 2,
             "event_definition_id": "d", "fields": {"k": "<b>bold</b>"}}
    _, content, _ = tb.compose_ticket(event)
    assert "<script>" not in content and "&lt;script&gt;" in content
    assert "&lt;b&gt;" in content


class MockGlpi(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _ok(self, obj):
        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.endswith("/initSession"):
            assert self.headers.get("Authorization", "").startswith("user_token ")
            return self._ok({"session_token": "sess123"})
        if self.path.endswith("/killSession"):
            return self._ok({})
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        if self.path.endswith("/Ticket"):
            inp = body["input"]
            MockGlpi.last_ticket = inp
            return self._ok({"id": 777})
        self.send_response(404)
        self.end_headers()


def test_handle_event_against_mock_glpi():
    srv = HTTPServer(("127.0.0.1", 0), MockGlpi)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    g = tb.Glpi(base=f"http://127.0.0.1:{srv.server_port}", app_token="a", user_token="u")
    with g:
        tid = g.create_ticket("тест", "<b>тело</b>", 5)
    srv.shutdown()
    assert tid == 777
    assert MockGlpi.last_ticket["urgency"] == 5


class _FakeGlpi:
    """Заглушка GLPI: считает созданные тикеты и followup'ы."""
    created = []
    followups = []
    status = 1

    def __init__(self, *a, **kw): pass
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def create_ticket(self, name, content, urgency=3):
        self.created.append(name); return 100 + len(self.created)
    def get_ticket(self, tid): return {"id": tid, "status": self.status}
    def add_followup(self, tid, content): self.followups.append((tid, content)); return {}


def _ev(msg, host="redos-server"):
    return {"id": "01M73KJHZ78KZBCJ3K0H2JRZ1H", "message": msg,
            "timestamp": "2026-11-09T16:00:00Z", "priority": 3,
            "event_definition_id": "d", "fields": {"host": host}}


def test_correlation_groups_same_host(tmp_path, monkeypatch):
    monkeypatch.setattr(tb, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(tb, "Glpi", _FakeGlpi)
    _FakeGlpi.created, _FakeGlpi.followups, _FakeGlpi.status = [], [], 1
    t1 = tb.handle_event(_ev("LNX - Брутфорс SSH"))
    t2 = tb.handle_event(_ev("LNX - Успешный вход root по SSH"))
    t3 = tb.handle_event(_ev("LNX - Обратная оболочка"))
    assert t1 == t2 == t3
    assert len(_FakeGlpi.created) == 1 and len(_FakeGlpi.followups) == 2
    assert "алерт №3" in _FakeGlpi.followups[-1][1]


def test_correlation_different_hosts_separate(tmp_path, monkeypatch):
    monkeypatch.setattr(tb, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(tb, "Glpi", _FakeGlpi)
    _FakeGlpi.created, _FakeGlpi.followups, _FakeGlpi.status = [], [], 1
    a = tb.handle_event(_ev("rule1", host="host-a"))
    b = tb.handle_event(_ev("rule2", host="host-b"))
    assert a != b and len(_FakeGlpi.created) == 2


def test_correlation_closed_ticket_new_one(tmp_path, monkeypatch):
    monkeypatch.setattr(tb, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(tb, "Glpi", _FakeGlpi)
    _FakeGlpi.created, _FakeGlpi.followups, _FakeGlpi.status = [], [], 1
    t1 = tb.handle_event(_ev("rule1"))
    _FakeGlpi.status = 6  # тикет закрыли
    t2 = tb.handle_event(_ev("rule1"))
    assert t2 != t1 and len(_FakeGlpi.created) == 2


def test_correlation_window_expired(tmp_path, monkeypatch):
    import sqlite3, time
    monkeypatch.setattr(tb, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(tb, "Glpi", _FakeGlpi)
    _FakeGlpi.created, _FakeGlpi.followups, _FakeGlpi.status = [], [], 1
    t1 = tb.handle_event(_ev("rule1"))
    con = sqlite3.connect(tmp_path / "state.db")  # «прошёл» 31 минуту
    con.execute("UPDATE incidents SET last_ts=? WHERE corr_key='redos-server'",
                (time.time() - 1860,)); con.commit(); con.close()
    t2 = tb.handle_event(_ev("rule1"))
    assert t2 != t1


# --- автозакрытие -----------------------------------------------------------

class _FakeGlpiClose(_FakeGlpi):
    closed = []
    def close_ticket(self, tid, comment):
        self.followups.append((tid, comment))
        self.closed.append(tid)
        self.status = 6
        return {}


def test_recovery_closes_ticket(tmp_path, monkeypatch):
    monkeypatch.setattr(tb, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(tb, "Glpi", _FakeGlpiClose)
    _FakeGlpiClose.created, _FakeGlpiClose.followups = [], []
    _FakeGlpiClose.closed, _FakeGlpiClose.status = [], 1
    t1 = tb.handle_event(_ev("HOMEREPO - Агент молчит больше суток"))
    tid = tb.handle_event(_ev("HOMEREPO - Агент вернулся на связь (agent_recovered)"))
    assert tid == t1
    assert _FakeGlpiClose.closed == [t1]
    assert "Восстановление" in _FakeGlpiClose.followups[-1][1]
    # инцидент удалён из состояния — следующий алерт создаст новый тикет
    t2 = tb.handle_event(_ev("HOMEREPO - Агент молчит больше суток"))
    assert t2 != t1 and len(_FakeGlpiClose.created) == 2


def test_recovery_without_incident_ignored(tmp_path, monkeypatch):
    monkeypatch.setattr(tb, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(tb, "Glpi", _FakeGlpiClose)
    _FakeGlpiClose.created, _FakeGlpiClose.closed = [], []
    tid = tb.handle_event(_ev("HOMEREPO - Агент вернулся на связь (agent_recovered)"))
    assert tid is None and _FakeGlpiClose.created == [] and _FakeGlpiClose.closed == []


def test_ttl_autoclose(tmp_path, monkeypatch):
    import sqlite3, time
    monkeypatch.setattr(tb, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(tb, "Glpi", _FakeGlpiClose)
    _FakeGlpiClose.created, _FakeGlpiClose.followups = [], []
    _FakeGlpiClose.closed, _FakeGlpiClose.status = [], 1
    t1 = tb.handle_event(_ev("LNX - Брутфорс SSH"))
    # прошло 25 часов тишины
    con = sqlite3.connect(tmp_path / "state.db")
    con.execute("UPDATE incidents SET last_ts=? WHERE corr_key='redos-server'",
                (time.time() - 90000,)); con.commit(); con.close()
    tid = tb.close_incident("redos-server", "<b>Автозакрытие:</b> тишина 24 ч.")
    assert tid == t1 and _FakeGlpiClose.closed == [t1]


def test_is_recovery_detection():
    assert tb.is_recovery({"message": "HOMEREPO - Агент вернулся на связь", "fields": {}})
    assert tb.is_recovery({"message": "x", "fields": {"hr_event": "agent_recovered"}})
    assert not tb.is_recovery({"message": "HOMEREPO - Агент молчит", "fields": {}})


# --- DFIR-IRIS v2/v3 ---------------------------------------------------------

def test_graylog_replay_url_uses_event_id_and_fallback(monkeypatch):
    monkeypatch.setattr(tb, "GRAYLOG", "https://graylog.test/")
    assert tb.graylog_replay_url(_ev("test")) == (
        "https://graylog.test/alerts/01M73KJHZ78KZBCJ3K0H2JRZ1H/replay-search")
    assert tb.graylog_replay_url({"message": "no id"}) == "https://graylog.test/alerts"
    assert tb.graylog_replay_url({"id": "unexpected/id"}) == (
        "https://graylog.test/alerts/unexpected%2Fid/replay-search")


class _FakeIrisResponse:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self):
        return json.dumps({"status": "success", "data": {"alert_id": 42}}).encode()


def test_send_iris_supports_v2_and_v3_endpoints(monkeypatch):
    requests = []
    monkeypatch.setattr(tb, "IRIS", "https://iris.test")
    monkeypatch.setattr(tb, "IRIS_KEY", "secret")
    monkeypatch.setattr(tb.urllib.request, "urlopen",
                        lambda request, **kwargs: requests.append(request) or _FakeIrisResponse())
    for path in ("/alerts/add", "/api/v2/alerts"):
        monkeypatch.setattr(tb, "IRIS_API_PATH", path)
        ok, alert_id = tb.send_iris(_ev("IRIS integration test"))
        assert ok and alert_id == "42"
    assert [request.full_url for request in requests] == [
        "https://iris.test/alerts/add", "https://iris.test/api/v2/alerts"]
    for request in requests:
        assert request.headers["Authorization"] == "Bearer secret"
        payload = json.loads(request.data)
        assert payload["alert_source"] == "Graylog"
        assert payload["alert_status_id"] == 2
        assert payload["alert_source_link"] == (
            "https://graylog.apps.monitoring.test/alerts/"
            "01M73KJHZ78KZBCJ3K0H2JRZ1H/replay-search")


class _FakeIrisV3Response(_FakeIrisResponse):
    def read(self):
        return json.dumps({"alert_id": 43, "alert_title": "created"}).encode()


def test_send_iris_accepts_direct_v3_response(monkeypatch):
    monkeypatch.setattr(tb, "IRIS", "https://iris.test")
    monkeypatch.setattr(tb, "IRIS_KEY", "secret")
    monkeypatch.setattr(tb, "IRIS_API_PATH", "/api/v2/alerts")
    monkeypatch.setattr(tb.urllib.request, "urlopen",
                        lambda request, **kwargs: _FakeIrisV3Response())
    ok, alert_id = tb.send_iris(_ev("IRIS v3 response test"))
    assert ok and alert_id == "43"


def test_send_iris_preserves_graylog_severity(monkeypatch):
    requests = []
    monkeypatch.setattr(tb, "IRIS", "https://iris.test")
    monkeypatch.setattr(tb, "IRIS_KEY", "secret")
    monkeypatch.setattr(tb.urllib.request, "urlopen",
                        lambda request, **kwargs: requests.append(request) or _FakeIrisResponse())
    for graylog_priority, iris_severity in ((1, 4), (2, 1), (3, 5)):
        event = _ev(f"priority {graylog_priority}")
        event["priority"] = graylog_priority
        ok, _ = tb.send_iris(event)
        assert ok
        payload = json.loads(requests[-1].data)
        assert payload["alert_severity_id"] == iris_severity


def test_low_and_medium_go_only_to_iris(tmp_path, monkeypatch):
    monkeypatch.setattr(tb, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(tb, "Glpi", _FakeGlpi)
    monkeypatch.setattr(tb, "send_gelf", lambda *args, **kwargs: None)
    _FakeGlpi.created, _FakeGlpi.followups = [], []
    sent = []

    def fake_iris(event):
        sent.append(event["priority"])
        return True, str(40 + event["priority"])

    monkeypatch.setattr(tb, "send_iris", fake_iris)
    for priority in (1, 2):
        event = _ev(f"[TEST] priority {priority}")
        event["priority"] = priority
        assert tb.handle_event(event) is None
    assert sent == [1, 2]
    assert _FakeGlpi.created == [] and _FakeGlpi.followups == []


def test_high_still_creates_glpi_and_iris(tmp_path, monkeypatch):
    monkeypatch.setattr(tb, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(tb, "Glpi", _FakeGlpi)
    monkeypatch.setattr(tb, "send_gelf", lambda *args, **kwargs: None)
    monkeypatch.setattr(tb, "send_iris", lambda event: (True, "45"))
    _FakeGlpi.created, _FakeGlpi.followups = [], []
    event = _ev("[TEST] HIGH")
    event["priority"] = 3
    assert tb.handle_event(event) == 101
    assert len(_FakeGlpi.created) == 1
