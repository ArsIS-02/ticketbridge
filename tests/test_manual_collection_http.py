import json
from http.server import HTTPServer
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


@pytest.fixture
def server(monkeypatch):
    monkeypatch.setattr(tb, "KEY", "test-key")
    monkeypatch.setattr(tb, "IRIS", ORIGIN)
    instance = HTTPServer(("127.0.0.1", 0), tb.Handler)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{instance.server_port}"
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=5)


def request(url, data=None, method=None, origin=ORIGIN):
    headers = {"Origin": origin}
    if data is not None:
        data = urlencode(data, doseq=True).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    return urllib.request.Request(url, data=data, headers=headers, method=method)


def multi_result(case_id, client_id, platform, artifacts, asset_id=None):
    return {
        "case_id": case_id, "asset_id": asset_id, "client_id": client_id,
        "platform": platform, "status": "completed", "batch_id": "abc123",
        "requested_artifacts": artifacts,
        "artifacts": [{"artifact": name, "flow_id": f"F.FLOW{index}",
                       "flow_link": f"https://velociraptor.example.test/F.FLOW{index}",
                       "state": "FINISHED", "row_count": 1}
                      for index, name in enumerate(artifacts)],
        "errors": [], "evidence_id": 17, "sha256": "abc123",
    }


def test_catalog_is_served_with_restricted_cors(server):
    with urllib.request.urlopen(request(server + "/velociraptor/catalog?key=test-key"),
                                timeout=5) as reply:
        payload = json.loads(reply.read())
        assert reply.status == 200
        assert reply.headers["Access-Control-Allow-Origin"] == ORIGIN
        assert reply.headers["Cache-Control"] == "no-store"
    assert payload["ok"] is True
    assert {item["id"] for item in payload["platforms"]} == {"linux", "darwin", "windows"}

    with urllib.request.urlopen(request(
            server + "/velociraptor/catalog?key=test-key", method="OPTIONS"), timeout=5) as reply:
        assert reply.status == 204
        assert reply.headers["Access-Control-Allow-Methods"] == "GET, OPTIONS"


def test_client_resolver_returns_id_with_restricted_cors(server, monkeypatch):
    calls = []

    def resolve(hostname):
        calls.append(hostname)
        return {"client_id": CLIENT, "hostname": "server-01",
                "fqdn": "server-01.example.test", "platform": "linux",
                "matched_by": "iris.asset_name"}

    monkeypatch.setattr(tb.manual_collection, "resolve_client_by_hostname", resolve)
    url = server + "/velociraptor/resolve-client?" + urlencode({
        "key": "test-key", "hostname": "server-01.example.test"})
    with urllib.request.urlopen(request(url), timeout=5) as reply:
        payload = json.loads(reply.read())
        assert reply.status == 200
        assert reply.headers["Access-Control-Allow-Origin"] == ORIGIN
        assert reply.headers["Cache-Control"] == "no-store"
    assert payload["ok"] is True and payload["client_id"] == CLIENT
    assert calls == ["server-01.example.test"]

    with urllib.request.urlopen(request(url, method="OPTIONS"), timeout=5) as reply:
        assert reply.status == 204
        assert reply.headers["Access-Control-Allow-Methods"] == "GET, OPTIONS"


def test_client_resolver_reports_ambiguity_without_starting_collection(server, monkeypatch):
    def resolve(hostname):
        error = ValueError("More than one Velociraptor client matched")
        error.code = "client_ambiguous"
        raise error

    monkeypatch.setattr(tb.manual_collection, "resolve_client_by_hostname", resolve)
    monkeypatch.setattr(tb.manual_collection, "collect_many_and_attach",
                        lambda *args, **kwargs: pytest.fail("collection must not run"))
    url = server + "/velociraptor/resolve-client?key=test-key&hostname=server-01"
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(request(url), timeout=5)
    assert caught.value.code == 409
    payload = json.loads(caught.value.read())
    assert payload["ok"] is False and payload["code"] == "client_ambiguous"


def test_modal_multi_collection_passes_platform_and_all_artifacts(server, monkeypatch):
    selected = ["Generic.Client.Info", "Linux.Sys.Pslist"]
    calls = []

    def collect(case_id, client_id, platform, artifacts, asset_id=None):
        calls.append((case_id, client_id, platform, artifacts, asset_id))
        return multi_result(case_id, client_id, platform, artifacts, asset_id)

    monkeypatch.setattr(tb.manual_collection, "collect_many_and_attach", collect)
    response = request(server + "/velociraptor/collect?key=test-key", {
        "case_id": "73", "asset_id": "1276", "client_id": CLIENT,
        "platform": "linux", "artifacts": selected,
        "confirm": "yes", "response": "json",
    })
    with urllib.request.urlopen(response, timeout=5) as reply:
        payload = json.loads(reply.read())
        assert reply.status == 200
    assert payload["ok"] is True and payload["status"] == "completed"
    assert payload["requested_artifacts"] == selected
    assert len(payload["artifacts"]) == 2
    assert calls == [(73, CLIENT, "linux", selected, 1276)]


@pytest.mark.parametrize("fields", [
    {"platform": "linux", "artifacts": []},
    {"platform": "linux", "artifacts": ["Generic.Client.Info", "Generic.Client.Info"]},
    {"platform": "linux", "artifacts": ["Windows.System.Pslist"]},
    {"platform": "darwin", "artifacts": ["Custom.Remediation.DeleteFile"]},
    {"platform": "windows", "artifacts": ["Windows.System.Pslist"], "vql": "SELECT * FROM exec()"},
    {"platform": "windows", "artifacts": ["Windows.System.Pslist"], "parameters": "{}"},
])
def test_invalid_multi_request_never_calls_collector(server, monkeypatch, fields):
    monkeypatch.setattr(tb.manual_collection, "collect_many_and_attach",
                        lambda *args, **kwargs: pytest.fail("collection must not run"))
    data = {"case_id": "73", "client_id": CLIENT,
            "confirm": "yes", "response": "json", **fields}
    response = request(server + "/velociraptor/collect?key=test-key", data)
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(response, timeout=5)
    assert caught.value.code == 400
    payload = json.loads(caught.value.read())
    assert payload["ok"] is False
