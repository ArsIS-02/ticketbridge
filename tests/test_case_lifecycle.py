import sqlite3

import pytest

import app


NOW = 1_800_000_000.0
KEY = "rule-1|host-a"
EVENT = {
    "id": "event-1",
    "message": "Test detection",
    "timestamp": "2027-01-15T10:11:12Z",
    "priority": 2,
    "event_definition_id": "rule-1",
    "fields": {"host": "host-a"},
}
ASSETS = [{"asset_name": "host-a", "asset_type_id": 3}]


def prepare(tmp_path, monkeypatch, *, case_state="open", alert_status=8,
            score=100, hits=2, case_closed_ts=None, last_evidence_ts=NOW,
            last_ts=NOW):
    monkeypatch.setattr(app, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(app.time, "time", lambda: NOW)
    monkeypatch.setattr(app, "EVIDENCE_PACK", True)
    monkeypatch.setattr(app, "CASE_EVIDENCE_INTERVAL", 3600)
    monkeypatch.setattr(app, "CASE_SUPPRESSION", 86400)
    monkeypatch.setattr(app, "CASE_REOPEN_MIN_WEIGHT", 50)
    monkeypatch.setattr(app, "_iris_alert_status", lambda alert_id: alert_status)
    monkeypatch.setattr(app, "_iris_case_state", lambda case_id: case_state)
    monkeypatch.setattr(app, "_iris_enrich", lambda *args: None)
    logs = []
    monkeypatch.setattr(app, "send_gelf", lambda *args, **kwargs: logs.append(kwargs))
    con = app.state_db()
    con.execute(
        "INSERT INTO iris_corr(corr_key, alert_id, score, hit_count, first_ts,"
        " last_ts, escalated, case_id, case_closed_ts, last_evidence_ts)"
        " VALUES(?,?,?,?,?,?,1,25,?,?)",
        (KEY, 1172, score, hits, NOW - 100, last_ts, case_closed_ts,
         last_evidence_ts))
    con.commit()
    con.close()
    return logs


def corr_row(tmp_path):
    con = sqlite3.connect(tmp_path / "state.db")
    row = con.execute(
        "SELECT alert_id, score, hit_count, case_id, case_closed_ts,"
        " last_evidence_ts FROM iris_corr WHERE corr_key=?", (KEY,)).fetchone()
    con.close()
    return row


def test_active_case_gets_timeline_event_and_initial_evidence(tmp_path, monkeypatch):
    logs = prepare(tmp_path, monkeypatch, last_evidence_ts=None,
                   last_ts=NOW - 3 * app.SCORE_WINDOW)
    requests = []
    evidence = []

    def request(method, path, payload=None):
        requests.append((method, path, payload))
        return True, {"event_id": 77}

    monkeypatch.setattr(app, "_iris_request", request)
    monkeypatch.setattr(app, "_attach_case_evidence",
                        lambda *args: evidence.append(args) or True)
    monkeypatch.setattr(app, "_post_iris",
                        lambda payload: pytest.fail("active case must not create alert"))

    ok, info = app._correlated_send(EVENT, {}, ASSETS, [])

    assert (ok, info) == (True, "1172")
    assert len(evidence) == 1
    method, path, payload = requests[0]
    assert (method, path) == ("POST", "/api/v2/cases/25/events")
    assert payload["event_date"] == "2027-01-15T10:11:12.000000"
    assert payload["event_tz"] == "+00:00"
    assert "host-a" in payload["event_title"]
    assert "скор 120" in payload["event_title"]
    assert "replay-search" in payload["event_title"]
    assert corr_row(tmp_path) == (1172, 120, 3, 25, None, NOW)
    assert any(item.get("tb_event") == "iris_case_enriched" for item in logs)


def test_case_evidence_refresh_is_throttled(tmp_path, monkeypatch):
    prepare(tmp_path, monkeypatch, last_evidence_ts=NOW - 10)
    evidence = []
    monkeypatch.setattr(app, "_iris_add_case_event", lambda *args, **kwargs: True)
    monkeypatch.setattr(app, "_attach_case_evidence",
                        lambda *args: evidence.append(args) or True)
    monkeypatch.setattr(app, "_post_iris",
                        lambda payload: pytest.fail("must not create alert"))

    assert app._correlated_send(EVENT, {}, ASSETS, [])[0]
    assert evidence == []
    assert corr_row(tmp_path)[5] == NOW - 10

    monkeypatch.setattr(app.time, "time", lambda: NOW + 3600)
    assert app._correlated_send(EVENT, {}, ASSETS, [])[0]
    assert len(evidence) == 1
    assert corr_row(tmp_path)[5] == NOW + 3600


def test_low_weight_repeat_after_close_is_suppressed(tmp_path, monkeypatch):
    logs = prepare(tmp_path, monkeypatch, case_state="closed")
    monkeypatch.setattr(app, "_post_iris",
                        lambda payload: pytest.fail("suppression must not create alert"))
    monkeypatch.setattr(app, "_iris_request",
                        lambda *args: pytest.fail("low weight must not reopen"))

    ok, info = app._correlated_send(EVENT, {}, ASSETS, [])

    assert (ok, info) == (True, "1172")
    assert corr_row(tmp_path) == (1172, 100, 2, 25, NOW, NOW)
    assert any(item.get("tb_event") == "iris_case_suppressed" for item in logs)


def test_weighted_repeat_reopens_same_case(tmp_path, monkeypatch):
    logs = prepare(tmp_path, monkeypatch, case_state="closed")
    event = dict(EVENT, priority=3)
    requests = []
    evidence = []

    def request(method, path, payload=None):
        requests.append((method, path, payload))
        return True, {"case_id": 25}

    monkeypatch.setattr(app, "_iris_request", request)
    monkeypatch.setattr(app, "_attach_case_evidence",
                        lambda *args: evidence.append(args) or True)
    monkeypatch.setattr(app, "_post_iris",
                        lambda payload: pytest.fail("reopen must not create alert"))

    ok, info = app._correlated_send(event, {}, ASSETS, [])

    assert (ok, info) == (True, "1172")
    assert (requests[0][0], requests[0][1]) == ("POST", "/api/v2/cases/25/reopen")
    assert requests[1][1] == "/api/v2/cases/25/events"
    assert "переоткрыт" in requests[1][2]["event_title"]
    assert len(evidence) == 1
    assert corr_row(tmp_path) == (1172, 150, 3, 25, None, NOW)
    assert any(item.get("tb_event") == "iris_case_reopened" for item in logs)


def test_reopen_failure_preserves_case_and_creates_no_alert(tmp_path, monkeypatch):
    logs = prepare(tmp_path, monkeypatch, case_state="closed")
    event = dict(EVENT, priority=3)
    monkeypatch.setattr(app, "_iris_request", lambda *args: (False, "API unavailable"))
    monkeypatch.setattr(app, "_post_iris",
                        lambda payload: pytest.fail("failed reopen must not create alert"))

    ok, info = app._correlated_send(event, {}, ASSETS, [])

    assert not ok and "reopen failed" in info
    assert corr_row(tmp_path) == (1172, 100, 2, 25, NOW, NOW)
    assert any(item.get("tb_event") == "iris_case_reopen_error" for item in logs)


def test_new_lifecycle_after_suppression_expires(tmp_path, monkeypatch):
    prepare(tmp_path, monkeypatch, case_state="closed", case_closed_ts=NOW - 86401)
    monkeypatch.setattr(app, "_post_iris", lambda payload: (True, "1200"))
    monkeypatch.setattr(app, "_iris_request",
                        lambda *args: pytest.fail("expired suppression must not reopen"))

    ok, info = app._correlated_send(EVENT, {}, ASSETS, [])

    assert (ok, info) == (True, "1200")
    assert corr_row(tmp_path) == (1200, 20, 1, None, None, None)


@pytest.mark.parametrize("alert_status,expected_ok", [(8, True), (6, False)])
def test_unknown_case_state_never_creates_duplicate(tmp_path, monkeypatch,
                                                     alert_status, expected_ok):
    logs = prepare(tmp_path, monkeypatch, case_state=None, alert_status=alert_status)
    monkeypatch.setattr(app, "_post_iris",
                        lambda payload: pytest.fail("unknown case state must not create alert"))

    ok, _ = app._correlated_send(EVENT, {}, ASSETS, [])

    assert ok is expected_ok
    assert corr_row(tmp_path)[3] == 25
    assert any(item.get("tb_event") == "iris_case_state_error" for item in logs)


def test_state_db_migrates_legacy_correlation_schema(tmp_path, monkeypatch):
    path = tmp_path / "legacy.db"
    monkeypatch.setattr(app, "STATE_DB", str(path))
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE iris_corr(
        corr_key TEXT PRIMARY KEY, alert_id INTEGER NOT NULL,
        score REAL NOT NULL DEFAULT 0, hit_count INTEGER NOT NULL DEFAULT 1,
        first_ts REAL, last_ts REAL,
        escalated INTEGER NOT NULL DEFAULT 0, case_id INTEGER)""")
    con.execute("INSERT INTO iris_corr VALUES('legacy', 10, 20, 1, 1, 2, 1, 25)")
    con.commit()
    con.close()

    con = app.state_db()
    columns = {row[1] for row in con.execute("PRAGMA table_info(iris_corr)")}
    row = con.execute("SELECT alert_id, case_id, case_closed_ts, last_evidence_ts"
                      " FROM iris_corr WHERE corr_key='legacy'").fetchone()
    con.close()

    assert {"case_closed_ts", "last_evidence_ts"} <= columns
    assert row == (10, 25, None, None)
