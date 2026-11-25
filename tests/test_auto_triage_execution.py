from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import sys
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import auto_triage as at
import auto_triage_execution as ex
import collection_playbooks as cp

RULE = "test-linux-process"
EVENT_ID = "synthetic-event"
CLIENT = "C.0000000000000001"
NOW = datetime(2026, 11, 23, 6, 0, tzinfo=timezone.utc)
ARTIFACTS = [
    "Generic.Client.Info",
    "Linux.Sys.Pslist",
    "Linux.Network.NetstatEnriched",
]


def registry():
    return cp.PlaybookRegistry({
        "schema_version": 1, "status": "dry_run_only",
        "max_client_age_seconds": 900,
        "playbooks": {"linux_process": {
            "platform": "linux", "mode": "manual", "timeout_seconds": 300,
            "row_limit": 10000, "time_window_seconds": 900,
            "artifacts": [
                {"name": "Generic.Client.Info", "parameter_builder": "empty"},
                {"name": "Linux.Sys.Pslist", "parameter_builder": "linux_pslist"},
                {"name": "Linux.Network.NetstatEnriched", "parameter_builder": "linux_netstat"},
            ]}},
        "rules": {RULE: {"playbook": "linux_process", "title": "Test process rule"}},
    })


def event(process="/usr/bin/socat"):
    return {
        "id": EVENT_ID, "event_definition_id": RULE,
        "timestamp": "2026-11-23T05:30:00Z", "message": "Synthetic test event",
        "fields": {"host": "server-01", "exe": process},
    }


def plan(process="/usr/bin/socat"):
    clients = [{
        "client_id": CLIENT, "last_seen_at": int(NOW.timestamp() * 1_000_000),
        "os_info": {"hostname": "server-01.example.test",
                    "fqdn": "server-01.example.test", "system": "linux"},
    }]
    policy = at.AutoTriagePolicy.from_env({
        "TB_VR_AUTO_TRIAGE": "dry_run", "TB_VR_AUTO_TRIAGE_RULES": RULE})
    return at.build_auto_plan(event(process), clients, policy, registry=registry(), now=NOW)


class FakeCollector:
    creator = "test-collector"

    def __init__(self, empty=False, fail_names=None):
        self.empty = empty
        self.fail_names = set(fail_names or [])
        self.calls = []

    @staticmethod
    def validate_client_id(value):
        assert value == CLIENT
        return value

    @staticmethod
    def flow_link(client_id, flow_id):
        return f"https://velociraptor.example.test/{client_id}/{flow_id}"

    def query(self, vql, timeout=None):
        self.calls.append((vql, timeout))
        if "Artifact.Server.Utils.CollectClient" in vql:
            name = next(name for name in ARTIFACTS if f"ArtifactName='{name}'" in vql)
            if name in self.fail_names:
                raise RuntimeError("synthetic collection failure")
            if self.empty:
                return []
            return [{"artifact": name, "value": "synthetic-row"}]
        if "FROM flows(" in vql:
            name = next(name for name in ARTIFACTS if f"'{name}' IN request.artifacts" in vql)
            index = ARTIFACTS.index(name) + 1
            return [{"session_id": f"F.TESTFLOW{index}", "state": "FINISHED",
                     "create_time": 1_795_000_000_000_000 + index,
                     "total_collected_rows": 0 if self.empty else 1}]
        raise AssertionError("Unexpected VQL: " + vql)


class FakePack:
    def __init__(self, error=None):
        self.error = error
        self.calls = []

    def attach(self, case_id, content, metadata):
        self.calls.append((case_id, content, metadata))
        if self.error:
            raise self.error
        return {"evidence_id": 77, "file_id": 88,
                "filename": metadata["filename"], "sha256": metadata["sha256"]}


def execute(tmp_path, collector=None, pack=None, item=None):
    return ex.execute_confirmed_plan(
        item or plan(), case_id=53, confirm_event_id=EVENT_ID,
        collector=collector or FakeCollector(), output_dir=tmp_path,
        registry=registry(), pack=pack, now=NOW)


def test_exact_event_confirmation_is_mandatory(tmp_path):
    collector = FakeCollector()
    with pytest.raises(ex.AutoTriageExecutionError, match="event_id"):
        ex.execute_confirmed_plan(
            plan(), case_id=53, confirm_event_id="wrong-event", collector=collector,
            output_dir=tmp_path, registry=registry())
    assert collector.calls == []


def test_on_mode_executes_only_after_same_confirmation(tmp_path):
    item = plan()
    item["auto_triage"]["mode"] = "on"
    result = execute(tmp_path, item=item)
    assert result["status"] == "completed"
    assert result["execution"]["authorized"] is True


def test_ineligible_plan_never_executes(tmp_path):
    item = plan()
    item["auto_triage"]["eligible"] = False
    collector = FakeCollector()
    with pytest.raises(ex.AutoTriageExecutionError, match="eligible"):
        execute(tmp_path, collector=collector, item=item)
    assert collector.calls == []


def test_tampered_artifact_list_never_executes(tmp_path):
    item = plan()
    item["artifacts"][1]["name"] = "Linux.Sys.Shell"
    collector = FakeCollector()
    with pytest.raises(ex.AutoTriageExecutionError, match="Artifact list"):
        execute(tmp_path, collector=collector, item=item)
    assert collector.calls == []


def test_successful_three_artifact_collection_and_verified_zip(tmp_path):
    collector = FakeCollector()
    pack = FakePack()
    result = execute(tmp_path, collector=collector, pack=pack)
    assert result["status"] == "completed"
    assert [item["artifact"] for item in result["artifacts"]] == ARTIFACTS
    assert result["execution"]["flow_created"] is True
    assert result["evidence"]["evidence_id"] == 77
    assert len(collector.calls) == 6
    collect_calls = [call for call in collector.calls if "CollectClient" in call[0]]
    assert len(collect_calls) == 3
    assert all(call[1] == 300 and "LIMIT 10000" in call[0] for call in collect_calls)

    output = Path(result["zip"]["path"])
    assert output.stat().st_mode & 0o777 == 0o600
    assert hashlib.sha256(output.read_bytes()).hexdigest() == result["zip"]["sha256"]
    with zipfile.ZipFile(output) as archive:
        assert len([name for name in archive.namelist()
                    if name.startswith("velociraptor/results/")]) == 3
        manifest = json.loads(archive.read("manifest.json"))
        for name, item in manifest["files"].items():
            raw = archive.read(name)
            assert hashlib.sha256(raw).hexdigest() == item["sha256"]
        stored = json.loads(archive.read("velociraptor/collection.json"))
        assert all("rows" not in item for item in stored["artifacts"])
    assert len(pack.calls) == 1
    assert pack.calls[0][2]["collection_errors"] == 0


def test_empty_rows_are_valid_completed_collection(tmp_path):
    result = execute(tmp_path, collector=FakeCollector(empty=True))
    assert result["status"] == "completed"
    assert all(item["row_count"] == 0 for item in result["artifacts"])


def test_partial_failure_is_recorded_and_packaged(tmp_path):
    result = execute(tmp_path, collector=FakeCollector(fail_names={"Linux.Sys.Pslist"}))
    assert result["status"] == "partial"
    assert len(result["artifacts"]) == 2
    assert result["errors"][0]["artifact"] == "Linux.Sys.Pslist"
    with zipfile.ZipFile(result["zip"]["path"]) as archive:
        errors = json.loads(archive.read("velociraptor/errors.json"))
        assert errors[0]["exception"] == "RuntimeError"


def test_all_failures_leave_error_zip_without_evidence_upload(tmp_path):
    pack = FakePack()
    result = execute(
        tmp_path, collector=FakeCollector(fail_names=ARTIFACTS), pack=pack)
    assert result["status"] == "failed"
    assert result["execution"]["flow_created"] is False
    assert len(result["errors"]) == 3
    assert Path(result["zip"]["path"]).exists()
    # An explicit case ID permits attaching even an error-only investigation pack.
    assert len(pack.calls) == 1


def test_parameters_cannot_escape_vql_string(tmp_path):
    collector = FakeCollector()
    result = execute(tmp_path, collector=collector, item=plan("x'); DELETE FROM flows(); --"))
    assert result["status"] == "completed"
    collect_vql = next(vql for vql, _ in collector.calls
                       if "CollectClient" in vql and "ArtifactName='Linux.Sys.Pslist'" in vql)
    assert "processRegex" in collect_vql
    assert "x'); DELETE FROM flows(); --" not in collect_vql
    assert ex._vql_string("a'b") == "'a\\'b'"


def test_limits_above_pilot_boundary_are_rejected(tmp_path):
    item = plan()
    item["playbook"]["row_limit"] = 10001
    collector = FakeCollector()
    with pytest.raises(ex.AutoTriageExecutionError, match="limits"):
        execute(tmp_path, collector=collector, item=item)
    assert collector.calls == []


def test_evidence_upload_error_preserves_local_zip(tmp_path):
    result = execute(tmp_path, pack=FakePack(RuntimeError("synthetic IRIS failure")))
    assert result["status"] == "completed"
    assert result["evidence"] is None
    assert result["evidence_error"]["exception"] == "RuntimeError"
    assert Path(result["zip"]["path"]).exists()
