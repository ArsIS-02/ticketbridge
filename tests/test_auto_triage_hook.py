import json
from pathlib import Path
import sqlite3
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app
import auto_triage_hook as hook

RULE = "test-linux-process"
EVENT = {
    "id": "event-auto-1", "event_definition_id": RULE,
    "timestamp": "2026-11-23T06:00:00Z", "message": "Synthetic auto event",
    "priority": 2, "fields": {"host": "server-01"},
}


@pytest.fixture(autouse=True)
def reset_state(monkeypatch):
    hook._ACTIVE["count"] = 0
    monkeypatch.setenv("TB_VR_AUTO_TRIAGE", "off")
    monkeypatch.setenv("TB_VR_AUTO_TRIAGE_RULES", RULE)
    monkeypatch.setenv("TB_VR_AUTO_TRIAGE_MAX_PARALLEL", "4")
    yield
    hook._ACTIVE["count"] = 0


def database(tmp_path, case_id=61):
    path = tmp_path / "state.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE iris_corr(alert_id INTEGER, escalated INTEGER,"
                " case_id INTEGER, last_ts REAL)")
    con.execute("INSERT INTO iris_corr VALUES(41,1,?,1)", (case_id,))
    con.commit()
    con.close()
    return path


def add_run(path, event_id=EVENT["id"]):
    con = hook._connect(path)
    con.execute(
        "INSERT INTO auto_triage_runs(event_id,event_definition_id,case_id,status,created_ts)"
        " VALUES(?,?,?,?,1)", (event_id, RULE, 61, "running"))
    con.commit()
    con.close()


def run_status(path, event_id=EVENT["id"]):
    con = sqlite3.connect(path)
    row = con.execute("SELECT status,result_json FROM auto_triage_runs WHERE event_id=?",
                      (event_id,)).fetchone()
    con.close()
    return row


class FakeThread:
    instances = []

    def __init__(self, target, args, daemon, name):
        self.target = target
        self.args = args
        self.daemon = daemon
        self.name = name
        self.started = False
        self.__class__.instances.append(self)

    def start(self):
        self.started = True


@pytest.fixture
def fake_threads(monkeypatch):
    FakeThread.instances = []
    monkeypatch.setattr(hook.threading, "Thread", FakeThread)
    return FakeThread.instances


def eligible_plan():
    return {"status": "dry_run", "artifacts": [{"name": "one"}],
            "auto_triage": {"eligible": True, "blocking_reasons": []}}


def test_off_is_noop_without_db_or_thread(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "_connect",
                        lambda *args: pytest.fail("off must not open DB"))
    monkeypatch.setattr(hook.threading, "Thread",
                        lambda *args, **kwargs: pytest.fail("off must not create thread"))
    assert hook.maybe_start(EVENT, 41, tmp_path / "missing.db") == "disabled"
    assert hook._ACTIVE["count"] == 0


def test_not_opted_in_is_noop(tmp_path, monkeypatch):
    monkeypatch.setenv("TB_VR_AUTO_TRIAGE", "on")
    monkeypatch.setenv("TB_VR_AUTO_TRIAGE_RULES", "another-rule")
    monkeypatch.setattr(hook, "_connect",
                        lambda *args: pytest.fail("non-opted rule must not open DB"))
    assert hook.maybe_start(EVENT, 41, tmp_path / "missing.db") == "rule_not_opted_in"


def test_dry_run_schedules_read_only_worker(tmp_path, monkeypatch, fake_threads):
    monkeypatch.setenv("TB_VR_AUTO_TRIAGE", "dry_run")
    path = database(tmp_path)
    assert hook.maybe_start(EVENT, 41, path) == "dry_run_started"
    assert len(fake_threads) == 1 and fake_threads[0].started
    assert fake_threads[0].args[1] == 61       # resolved case_id
    assert fake_threads[0].args[4] is False   # no persistent execution claim
    assert hook._ACTIVE["count"] == 1         # fake worker has not released yet


def test_on_claims_event_and_duplicate_never_starts_twice(tmp_path, monkeypatch, fake_threads):
    monkeypatch.setenv("TB_VR_AUTO_TRIAGE", "on")
    path = database(tmp_path)
    assert hook.maybe_start(EVENT, 41, path) == "started"
    assert run_status(path)[0] == "running"
    assert hook.maybe_start(EVENT, 41, path) == "duplicate"
    assert len(fake_threads) == 1


def test_on_requires_existing_case_and_releases_reservation(tmp_path, monkeypatch, fake_threads):
    monkeypatch.setenv("TB_VR_AUTO_TRIAGE", "on")
    path = database(tmp_path, case_id=None)
    assert hook.maybe_start(EVENT, 41, path) == "case_not_available"
    assert fake_threads == [] and hook._ACTIVE["count"] == 0


def test_parallel_limit_returns_busy(tmp_path, monkeypatch):
    monkeypatch.setenv("TB_VR_AUTO_TRIAGE", "on")
    monkeypatch.setenv("TB_VR_AUTO_TRIAGE_MAX_PARALLEL", "1")
    hook._ACTIVE["count"] = 1
    assert hook.maybe_start(EVENT, 41, database(tmp_path)) == "busy"
    assert hook._ACTIVE["count"] == 1


def test_dry_run_worker_never_calls_executor(tmp_path, monkeypatch):
    path = database(tmp_path)
    logs = []
    monkeypatch.setenv("TB_VR_AUTO_TRIAGE", "dry_run")
    monkeypatch.setattr(hook, "_collector", lambda env: object())
    monkeypatch.setattr(hook.auto_triage, "plan_from_environment",
                        lambda *args, **kwargs: eligible_plan())
    monkeypatch.setattr(hook.auto_triage_execution, "execute_confirmed_plan",
                        lambda *args, **kwargs: pytest.fail("dry-run must not execute"))
    hook._ACTIVE["count"] = 1
    hook._worker(EVENT, 61, 41, path, False,
                 lambda short, **fields: logs.append((short, fields)))
    assert hook._ACTIVE["count"] == 0
    assert logs[0][1]["tb_event"] == "auto_triage_dry_run"


def test_on_worker_records_completed_result(tmp_path, monkeypatch):
    path = database(tmp_path)
    add_run(path)
    logs = []
    monkeypatch.setenv("TB_VR_AUTO_TRIAGE", "on")
    monkeypatch.setattr(hook, "_collector", lambda env: object())
    monkeypatch.setattr(hook, "PlaybookRegistry", type("Registry", (), {
        "load": staticmethod(lambda: object())}))
    monkeypatch.setattr(hook, "EvidencePack", lambda *args: object())
    monkeypatch.setattr(hook.auto_triage, "plan_from_environment",
                        lambda *args, **kwargs: eligible_plan())
    result = {
        "status": "completed", "artifacts": [{"artifact": "one"}], "errors": [],
        "evidence": {"evidence_id": 56}, "evidence_error": None,
        "zip": {"filename": "evidence.zip"},
    }
    monkeypatch.setattr(hook.auto_triage_execution, "execute_confirmed_plan",
                        lambda *args, **kwargs: result)
    hook._ACTIVE["count"] = 1
    hook._worker(EVENT, 61, 41, path, True,
                 lambda short, **fields: logs.append((short, fields)))
    status, raw = run_status(path)
    assert status == "completed" and json.loads(raw)["evidence"]["evidence_id"] == 56
    assert hook._ACTIVE["count"] == 0
    assert logs[0][1]["tb_event"] == "auto_triage_finished"


def test_blocked_worker_does_not_execute_and_records_reason(tmp_path, monkeypatch):
    path = database(tmp_path)
    add_run(path)
    monkeypatch.setenv("TB_VR_AUTO_TRIAGE", "on")
    monkeypatch.setattr(hook, "_collector", lambda env: object())
    blocked = {"status": "dry_run",
               "auto_triage": {"eligible": False, "blocking_reasons": ["client_offline"]}}
    monkeypatch.setattr(hook.auto_triage, "plan_from_environment",
                        lambda *args, **kwargs: blocked)
    monkeypatch.setattr(hook.auto_triage_execution, "execute_confirmed_plan",
                        lambda *args, **kwargs: pytest.fail("blocked plan must not execute"))
    hook._ACTIVE["count"] = 1
    hook._worker(EVENT, 61, 41, path, True, None)
    assert run_status(path)[0] == "blocked"
    assert "client_offline" in run_status(path)[1]
    assert hook._ACTIVE["count"] == 0


def test_worker_exception_isolated_and_recorded(tmp_path, monkeypatch):
    path = database(tmp_path)
    add_run(path)
    monkeypatch.setenv("TB_VR_AUTO_TRIAGE", "on")
    monkeypatch.setattr(hook, "_collector", lambda env: object())
    monkeypatch.setattr(hook.auto_triage, "plan_from_environment",
                        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("synthetic")))
    hook._ACTIVE["count"] = 1
    hook._worker(EVENT, 61, 41, path, True, None)
    status, raw = run_status(path)
    assert status == "error" and json.loads(raw)["exception"] == "RuntimeError"
    assert hook._ACTIVE["count"] == 0


def test_handle_event_schedules_only_after_iris_success(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(app, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(app, "with_maintenance_context", lambda event: event)
    monkeypatch.setattr(app, "maintenance_is_active", lambda event: False)
    monkeypatch.setattr(app, "send_gelf", lambda *args, **kwargs: None)
    monkeypatch.setattr(app, "send_iris", lambda event: (True, "41"))
    monkeypatch.setattr(app.auto_triage_hook, "maybe_start",
                        lambda *args, **kwargs: calls.append(args) or "started")
    app.handle_event(dict(EVENT))
    assert len(calls) == 1
    assert calls[0][1] == "41" and calls[0][2] == str(tmp_path / "state.db")

    monkeypatch.setattr(app, "send_iris", lambda event: (False, "synthetic IRIS error"))
    app.handle_event(dict(EVENT))
    assert len(calls) == 1
