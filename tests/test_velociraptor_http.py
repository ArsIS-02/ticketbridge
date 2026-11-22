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
        yield f"http://127.0.0.1:{instance.server_port}/velociraptor/collect?key=test-key"
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=5)


def request(url, data=None, method=None, origin=ORIGIN):
    headers = {"Origin": origin}
    if data is not None:
        data = urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    return urllib.request.Request(url, data=data, headers=headers, method=method)


def result(case_id, client_id, asset_id=None):
    return {
        "case_id": case_id,
        "asset_id": asset_id,
        "client_id": client_id,
        "flow_id": "F.TESTFLOW",
        "evidence_id": 17,
        "sha256": "abc123",
        "flow_link": f"https://velociraptor.example.test/{client_id}/F.TESTFLOW",
    }


def test_modal_json_collection_includes_asset_and_restricted_cors(server, monkeypatch):
    calls = []
    monkeypatch.setattr(
        tb.velociraptor_evidence, "collect_and_attach",
        lambda case_id, client_id, asset_id=None: (
            calls.append((case_id, client_id, asset_id)) or result(case_id, client_id, asset_id)))
    response = request(server, {
        "case_id": "53", "asset_id": "42", "client_id": CLIENT,
        "confirm": "yes", "response": "json",
    })
    with urllib.request.urlopen(response, timeout=5) as reply:
        payload = json.loads(reply.read())
        assert reply.status == 200
        assert reply.headers["Access-Control-Allow-Origin"] == ORIGIN
        assert reply.headers["Cache-Control"] == "no-store"
    assert payload["ok"] is True
    assert payload["asset_id"] == 42
    assert calls == [(53, CLIENT, 42)]

    with urllib.request.urlopen(request(server, {
        "case_id": "53", "client_id": CLIENT, "confirm": "yes", "response": "json",
    }, origin="https://attacker.example.test"), timeout=5) as reply:
        assert reply.headers.get("Access-Control-Allow-Origin") is None


def test_modal_rejects_missing_confirmation_without_collection(server, monkeypatch):
    monkeypatch.setattr(
        tb.velociraptor_evidence, "collect_and_attach",
        lambda *args, **kwargs: pytest.fail("collection must not run"))
    response = request(server, {
        "case_id": "53", "client_id": CLIENT, "response": "json",
    })
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(response, timeout=5)
    assert caught.value.code == 400
    payload = json.loads(caught.value.read())
    assert payload["ok"] is False
    assert "confirmation" in payload["error"]


def test_modal_preflight_is_limited_to_collection_route(server):
    with urllib.request.urlopen(request(server, method="OPTIONS"), timeout=5) as reply:
        assert reply.status == 204
        assert reply.headers["Access-Control-Allow-Origin"] == ORIGIN
        assert reply.headers["Access-Control-Allow-Methods"] == "POST, OPTIONS"
