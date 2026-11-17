import hashlib
import io
import json
from pathlib import Path
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app
import iris_evidence_pack as ep


class FakePack(ep.EvidencePack):
    def __init__(self):
        super().__init__("https://iris", "key", "https://graylog", "token")
        self.searches = []
        self.uploads = []
        self.expected_hash = ""
        self.filename = ""

    def api(self, method, path, payload=None, content_type="application/json"):
        if path == "/api/v2/cases/25" and method == "GET":
            return {"case_id": 25, "case_name": "Test case"}
        if path == "/api/v2/alerts?case_id=25&per_page=200":
            return {"data": [{
                "alert_id": 1172, "alert_title": "Test alert",
                "alert_source_link": "https://graylog/replay",
                "alert_source_content": {"replay_info": {
                    "query": "audit", "timerange_start": "start", "timerange_end": "end",
                    "streams": ["audit-stream"]}},
                "assets": [{"asset_name": "redos-server", "asset_type_id": 3}],
                "iocs": [], "modification_history": {"1": {"action": "created"}},
            }]}
        if path.startswith("/api/v2/alerts/1172/comments"):
            return {"data": [{"comment_id": 1, "comment_text": "enriched"}]}
        if path.endswith("/assets?per_page=200") or path.endswith("/iocs?per_page=200"):
            return {"data": []}
        if path.endswith("/events?per_page=200"):
            return {"tim": [{"event_id": 1}]}
        if path.endswith("/notes"):
            return {"data": []}
        if path.endswith("/evidences?per_page=200") and method == "GET":
            return {"data": ([{"id": 7, "filename": self.filename}] if self.filename else [])}
        if path.endswith("/datastore/tree"):
            return {"d-5": {"name": "Case 25", "type": "directory", "is_root": True,
                            "children": {"d-6": {"name": "Evidences", "type": "directory",
                                                 "children": {}}}}}
        if path == "/api/v2/cases/25/datastore/folders/6/files" and method == "POST":
            self.uploads.append((payload, content_type))
            return {"file_id": 99}
        if path == "/api/v2/cases/25/datastore/files/99/info":
            return {"file_sha256": self.expected_hash}
        raise AssertionError((method, path))

    def graylog_search(self, query, start, end, streams):
        self.searches.append((query, start, end, streams))
        return [{"source": "redos-server", "message": query}]


def test_pack_contains_evidence_and_valid_manifest():
    pack = FakePack()
    content, metadata = pack.build(25, 1172, {"message": "latest"}, 100, 3)
    assert metadata["original_event_count"] == 1
    assert metadata["context_event_count"] == 1
    assert pack.searches[0][3] == ["audit-stream"]
    assert pack.searches[1][3] == []  # контекст ищется по всем стримам
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        names = set(archive.namelist())
        assert {"README.md", "manifest.json", "iris/case.json", "iris/alerts.json",
                "graylog/original_events.json", "graylog/context_events.json"} <= names
        manifest = json.loads(archive.read("manifest.json"))
        for name, entry in manifest["files"].items():
            raw = archive.read(name)
            assert len(raw) == entry["size"]
            assert hashlib.sha256(raw).hexdigest() == entry["sha256"]
        readme = archive.read("README.md").decode()
        assert "кейс IRIS №25" in readme
        assert "https://graylog/replay" in readme


def test_attach_uses_evidence_folder_and_verifies_hash():
    pack = FakePack()
    content = b"zip-content"
    metadata = {"filename": "case-25-evidence.zip", "generated_at": "now",
                "sha256": hashlib.sha256(content).hexdigest(), "size": len(content),
                "original_event_count": 1, "context_event_count": 2,
                "collection_errors": 0}
    pack.expected_hash = metadata["sha256"]
    pack.filename = metadata["filename"]
    result = pack.attach(25, content, metadata)
    assert result["file_id"] == 99 and result["evidence_id"] == 7
    body, content_type = pack.uploads[0]
    assert content_type.startswith("multipart/form-data; boundary=")
    assert b'name="file_is_evidence"' in body
    assert b"true" in body
    assert body.endswith(b"--\r\n")


def test_escalation_survives_evidence_pack_failure(monkeypatch):
    logs = []
    monkeypatch.setattr(app, "EVIDENCE_PACK", True)
    monkeypatch.setattr(app, "_iris_escalate", lambda *args: (99, ""))
    monkeypatch.setattr(app, "send_gelf", lambda *args, **kwargs: logs.append(kwargs))
    monkeypatch.setattr(app.iris_evidence_pack, "build_and_attach",
                        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("test failure")))
    case_id = app._escalate_correlated(1172, {"event_definition_title": "Rule"},
                                       "rule|host", 100, 2)
    assert case_id == 99
    assert any(item.get("tb_event") == "iris_evidence_pack_error" for item in logs)
    assert any(item.get("tb_event") == "iris_escalated" for item in logs)


def test_escalation_attaches_pack(monkeypatch):
    logs = []
    called = {}
    monkeypatch.setattr(app, "EVIDENCE_PACK", True)
    monkeypatch.setattr(app, "_iris_escalate", lambda *args: (99, ""))
    monkeypatch.setattr(app, "send_gelf", lambda *args, **kwargs: logs.append(kwargs))

    def attach(**kwargs):
        called.update(kwargs)
        return {"filename": "pack.zip", "file_id": 1, "evidence_id": 2}

    monkeypatch.setattr(app.iris_evidence_pack, "build_and_attach", attach)
    assert app._escalate_correlated(1172, {}, "rule|host", 100, 2) == 99
    assert called["case_id"] == 99 and called["alert_id"] == 1172
    assert called["score"] == 100 and called["hits"] == 2
    assert any(item.get("tb_event") == "iris_evidence_pack" for item in logs)
