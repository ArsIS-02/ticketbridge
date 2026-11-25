import json
from http.server import ThreadingHTTPServer
from pathlib import Path
import sys
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app as tb

CLIENT = "C.0123456789abcdef"
ORIGIN = "https://iris.example.test"


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setattr(tb, "KEY", "test-key")
    monkeypatch.setattr(tb, "IRIS", ORIGIN)
    monkeypatch.setattr(tb, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(tb, "_COLLECTION_JOBS", None)
    instance = ThreadingHTTPServer(("127.0.0.1", 0), tb.Handler)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{instance.server_port}"
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=5)


def request(url, fields=None, method=None):
    data = None
    headers = {"Origin": ORIGIN, "Accept": "application/json"}
    if fields is not None:
        data = urlencode(fields, doseq=True).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}, response.headers
    except urllib.error.HTTPError as error:
        raw = error.read()
        return error.code, json.loads(raw) if raw else {}, error.headers


def wait_job(server, job_id):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        status, payload, _ = request(server + f"/velociraptor/jobs/{job_id}?key=test-key")
        assert status == 200 and payload["ok"] is True
        if payload["job"]["status"] not in ("queued", "collecting", "uploading"):
            return payload["job"]
        time.sleep(0.01)
    raise AssertionError("job did not finish")


def fields(**changes):
    data = {"case_id": "73", "asset_id": "42", "client_id": CLIENT,
            "platform": "linux", "artifacts": ["Generic.Client.Info"],
            "confirm": "yes", "response": "json", "async": "1"}
    data.update(changes)
    return data


def collection_result(case_id=73):
    return {"case_id": case_id, "asset_id": 42, "client_id": CLIENT,
            "platform": "linux", "status": "completed", "batch_id": "batch-1",
            "requested_artifacts": ["Generic.Client.Info"],
            "artifacts": [{"artifact": "Generic.Client.Info", "flow_id": "F.TEST",
                           "flow_link": "https://velociraptor.example.test/F.TEST",
                           "state": "FINISHED", "row_count": 1}],
            "errors": [], "evidence_id": 17, "filename": "case-73-test.zip",
            "sha256": "abc123"}


def test_case_async_job_returns_immediately_and_exposes_persistent_status(server, monkeypatch):
    release = threading.Event()
    started = threading.Event()

    def collect(case_id, client_id, platform, artifacts, asset_id=None, progress=None):
        started.set()
        assert release.wait(2)
        assert progress
        progress("uploading")
        return collection_result(case_id)

    monkeypatch.setattr(tb.manual_collection, "collect_many_and_attach", collect)
    status, payload, _ = request(server + "/velociraptor/collect?key=test-key", fields())
    assert status == 202 and payload["ok"] is True
    job_id = payload["job"]["job_id"]
    assert started.wait(1)
    status, duplicate, _ = request(server + "/velociraptor/collect?key=test-key", fields())
    assert status == 200 and duplicate["duplicate"] is True
    assert duplicate["job"]["job_id"] == job_id
    release.set()
    final = wait_job(server, job_id)
    assert final["status"] == "completed"
    assert final["result"]["evidence_id"] == 17
    status, latest, headers = request(server + "/velociraptor/jobs?key=test-key&case_id=73")
    assert status == 200 and latest["job"]["job_id"] == job_id
    assert headers["Access-Control-Allow-Origin"] == ORIGIN
    assert headers["Cache-Control"] == "no-store"


def test_alert_async_job_reuses_linked_incident_and_adds_completion_comment(server, monkeypatch):
    comments = []

    def iris_request(method, path, payload=None):
        return True, {"alert_id": 53, "alert_title": "Test", "cases": [73],
                      "assets": [{"asset_id": 42, "asset_uuid": "asset-42",
                                  "asset_name": "redos-host"}]}

    monkeypatch.setattr(tb, "_iris_request", iris_request)
    monkeypatch.setattr(tb, "_iris_add_comment",
                        lambda alert_id, text: comments.append((alert_id, text)) or (True, {}))
    monkeypatch.setattr(tb.manual_collection, "collect_many_and_attach",
                        lambda case_id, client_id, platform, artifacts, asset_id=None, progress=None:
                        collection_result(case_id))
    data = fields(alert_id="53")
    del data["case_id"]
    status, payload, _ = request(server + "/velociraptor/alert-collect?key=test-key", data)
    assert status == 202
    final = wait_job(server, payload["job"]["job_id"])
    assert final["status"] == "completed" and final["case_id"] == 73
    assert final["result"]["case_created"] is False
    assert comments and comments[0][0] == 53
    assert "Evidence ID: `17`" in comments[0][1]
    assert "F.TEST" in comments[0][1]


@pytest.mark.parametrize("query", [
    "key=bad", "key=test-key&case_id=0", "key=test-key",
    "key=test-key&case_id=73&alert_id=53", "key=test-key&case_id=73&unknown=1",
])
def test_job_queries_are_authenticated_and_validated(server, query):
    status, payload, _ = request(server + "/velociraptor/jobs?" + query)
    assert status in (400, 403)
    assert payload.get("ok", False) is False


def test_unknown_and_malformed_job_ids_return_clean_errors(server):
    status, _, _ = request(server + "/velociraptor/jobs/not-a-job?key=test-key")
    assert status == 400
    status, _, _ = request(server + "/velociraptor/jobs/" + "0" * 32 + "?key=test-key")
    assert status == 404
    status, _, headers = request(
        server + "/velociraptor/jobs?key=test-key&case_id=73", method="OPTIONS")
    assert status == 204
    assert headers["Access-Control-Allow-Methods"] == "GET, OPTIONS"
