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
    return {"message": msg, "timestamp": "2026-11-09T16:00:00Z", "priority": 3,
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
