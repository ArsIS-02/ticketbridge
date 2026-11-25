import json
from http.server import ThreadingHTTPServer
from pathlib import Path
import sys
import threading
import urllib.error
import urllib.request
from urllib.parse import urlencode

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app as tb

CLIENT = "C.0123456789abcdef"
ORIGIN = "https://iris.example.test"
ASSET = {"asset_id": 42, "asset_uuid": "asset-uuid-42", "asset_name": "redos-host"}


@pytest.fixture
def server(monkeypatch):
    monkeypatch.setattr(tb, "KEY", "test-key")
    monkeypatch.setattr(tb, "IRIS", ORIGIN)
    instance = ThreadingHTTPServer(("127.0.0.1", 0), tb.Handler)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{instance.server_port}/velociraptor/alert-collect?key=test-key"
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=5)


def post(url, fields):
    request = urllib.request.Request(
        url, data=urlencode(fields, doseq=True).encode(), method="POST",
        headers={"Origin": ORIGIN, "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def fields(**changes):
    result = {"alert_id": "53", "asset_id": "42", "client_id": CLIENT,
              "platform": "linux", "artifacts": ["Generic.Client.Info"],
              "confirm": "yes", "response": "json"}
    result.update(changes)
    return result


def alert(cases=None):
    return {"alert_id": 53, "alert_title": "Test alert", "assets": [ASSET],
            "cases": cases or []}


def collection_result(case_id, asset_id=None):
    return {"case_id": case_id, "asset_id": asset_id, "client_id": CLIENT,
            "platform": "linux", "status": "completed", "batch_id": "batch-1",
            "requested_artifacts": ["Generic.Client.Info"],
            "artifacts": [{"artifact": "Generic.Client.Info", "flow_id": "F.TEST",
                           "flow_link": "https://velociraptor.example.test/F.TEST",
                           "state": "FINISHED", "row_count": 1}],
            "errors": [], "evidence_id": 17, "sha256": "abc123"}


def test_existing_linked_incident_is_reused(server, monkeypatch):
    calls = []

    def iris_request(method, path, payload=None):
        calls.append((method, path, payload))
        return True, alert([73])

    monkeypatch.setattr(tb, "_iris_request", iris_request)
    monkeypatch.setattr(tb.manual_collection, "collect_many_and_attach",
                        lambda case_id, client_id, platform, artifacts, asset_id=None:
                        collection_result(case_id, asset_id))
    status, payload = post(server, fields())
    assert status == 200 and payload["ok"] is True
    assert payload["case_id"] == 73 and payload["case_created"] is False
    assert payload["alert_id"] == 53
    assert calls == [("GET", "/api/v2/alerts/53", None)]


def test_unlinked_alert_is_escalated_with_selected_asset(server, monkeypatch):
    calls = []

    def iris_request(method, path, payload=None):
        calls.append((method, path, payload))
        if method == "GET":
            return True, alert()
        return True, {"case_id": 91}

    monkeypatch.setattr(tb, "_iris_request", iris_request)
    monkeypatch.setattr(tb.manual_collection, "collect_many_and_attach",
                        lambda case_id, client_id, platform, artifacts, asset_id=None:
                        collection_result(case_id, asset_id))
    status, payload = post(server, fields())
    assert status == 200 and payload["case_id"] == 91
    assert payload["case_created"] is True
    method, path, body = calls[1]
    assert (method, path) == ("POST", "/api/v2/alerts/escalate/53")
    assert body["assets_import_list"] == ["asset-uuid-42"]
    assert body["import_as_event"] is True
    assert "manual-triage" in body["case_tags"]


@pytest.mark.parametrize("changes", [
    {"confirm": "no"},
    {"vql": "SELECT * FROM exec()"},
    {"artifacts": []},
])
def test_invalid_alert_request_does_not_read_or_collect(server, monkeypatch, changes):
    monkeypatch.setattr(tb, "_iris_request",
                        lambda *args: pytest.fail("IRIS must not be called"))
    monkeypatch.setattr(tb.manual_collection, "collect_many_and_attach",
                        lambda *args, **kwargs: pytest.fail("collection must not run"))
    status, payload = post(server, fields(**changes))
    assert status == 400 and payload["ok"] is False


def test_asset_from_another_alert_is_rejected_before_escalation(server, monkeypatch):
    calls = []
    monkeypatch.setattr(tb, "_iris_request",
                        lambda *args: (calls.append(args) or (True, alert([73]))))
    monkeypatch.setattr(tb.manual_collection, "collect_many_and_attach",
                        lambda *args, **kwargs: pytest.fail("collection must not run"))
    status, payload = post(server, fields(asset_id="999"))
    assert status == 400 and "does not belong" in payload["error"]
    assert calls == [("GET", "/api/v2/alerts/53")]


def test_parallel_duplicate_is_rejected_and_later_repeat_is_allowed(server, monkeypatch):
    started = threading.Event()
    release = threading.Event()
    collect_calls = []

    def iris_request(method, path, payload=None):
        return True, alert([73])

    def collect(case_id, client_id, platform, artifacts, asset_id=None):
        collect_calls.append(case_id)
        started.set()
        assert release.wait(3)
        return collection_result(case_id, asset_id)

    monkeypatch.setattr(tb, "_iris_request", iris_request)
    monkeypatch.setattr(tb.manual_collection, "collect_many_and_attach", collect)
    first = {}

    def run_first():
        first["response"] = post(server, fields())

    thread = threading.Thread(target=run_first)
    thread.start()
    assert started.wait(2)
    status, payload = post(server, fields())
    assert status == 409 and "already running" in payload["error"]
    release.set()
    thread.join(timeout=5)
    assert first["response"][0] == 200
    status, payload = post(server, fields())
    assert status == 200 and payload["case_id"] == 73
    assert collect_calls == [73, 73]


def test_failure_reports_new_incident_and_retry_does_not_escalate_again(server, monkeypatch):
    current_alert = alert()
    attempts = []

    def iris_request(method, path, payload=None):
        if method == "POST":
            current_alert["cases"] = [91]
        return True, current_alert if method == "GET" else {"case_id": 91}

    def collect(case_id, client_id, platform, artifacts, asset_id=None):
        attempts.append(case_id)
        if len(attempts) == 1:
            raise RuntimeError("synthetic collector outage")
        return collection_result(case_id, asset_id)

    monkeypatch.setattr(tb, "_iris_request", iris_request)
    monkeypatch.setattr(tb.manual_collection, "collect_many_and_attach", collect)
    status, payload = post(server, fields())
    assert status == 502 and payload["case_id"] == 91
    assert payload["case_created"] is True
    status, payload = post(server, fields())
    assert status == 200 and payload["case_id"] == 91
    assert payload["case_created"] is False
    assert attempts == [91, 91]
