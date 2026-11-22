import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import velociraptor_evidence as vr

CLIENT = "C.0123456789abcdef"
FLOW = "F.DC09UAVUFI1HM"


def completed(data=None, code=0, error=""):
    return subprocess.CompletedProcess([], code, json.dumps(data or []), error)


@pytest.fixture
def api_config(tmp_path):
    path = tmp_path / "api.yaml"
    path.write_text("test-only")
    path.chmod(0o600)
    return path


def collector(api_config, runner):
    return vr.VelociraptorCollector("/opt/velociraptor", api_config,
                                    "https://velociraptor", "test-collector",
                                    runner=runner)


def test_rejects_invalid_client_and_permissions(api_config):
    client = collector(api_config, lambda *a, **k: completed())
    with pytest.raises(vr.VelociraptorError, match="client_id"):
        client.collect("hostname; DELETE")
    api_config.chmod(0o644)
    with pytest.raises(vr.VelociraptorError, match="0600"):
        client.query("SELECT 1")


def test_api_error_and_invalid_json(api_config):
    client = collector(api_config, lambda *a, **k: completed(code=1, error="denied"))
    with pytest.raises(vr.VelociraptorError, match="denied"):
        client.query("SELECT 1")
    client = collector(api_config, lambda *a, **k: subprocess.CompletedProcess([], 0, "not-json", ""))
    with pytest.raises(vr.VelociraptorError, match="invalid JSON"):
        client.query("SELECT 1")


def test_timeout(api_config):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])
    client = collector(api_config, timeout)
    with pytest.raises(vr.VelociraptorError, match="timed out"):
        client.query("SELECT 1")


def test_missing_client_and_empty_result(api_config):
    client = collector(api_config, lambda *a, **k: completed([]))
    with pytest.raises(vr.VelociraptorError, match="not found"):
        client.collect(CLIENT)

    calls = []
    def no_results(command, **kwargs):
        calls.append(command[-1])
        if "clients()" in command[-1]:
            return completed([{"client_id": CLIENT}])
        return completed([])
    client = collector(api_config, no_results)
    with pytest.raises(vr.VelociraptorError, match="without result"):
        client.collect(CLIENT)
    assert "Artifact.Server.Utils.CollectClient" in calls[1]


def test_successful_pack_and_attach(api_config):
    rows = [{"Param": "Hostname", "Value": "test-host"}]
    flow = {"session_id": FLOW, "state": "FINISHED", "create_time": 123}
    def run(command, **kwargs):
        query = command[-1]
        if "clients()" in query:
            return completed([{"client_id": CLIENT}])
        if "Artifact.Server.Utils.CollectClient" in query:
            assert "Generic.Client.Info" in query and "Parameters='{}'" in query
            return completed(rows)
        return completed([flow])
    client = collector(api_config, run)
    actual_rows, actual_flow = client.collect(CLIENT)
    assert actual_rows == rows and actual_flow == flow
    content, metadata, collection = client.build_pack(25, CLIENT, rows, flow)
    assert collection["flow_id"] == FLOW
    assert collection["flow_link"] == (
        f"https://velociraptor/app/index.html?org_id=root#/collected/{CLIENT}/{FLOW}")
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        assert json.loads(archive.read("velociraptor/results.json")) == rows
        manifest = json.loads(archive.read("manifest.json"))
        for name, item in manifest["files"].items():
            raw = archive.read(name)
            assert hashlib.sha256(raw).hexdigest() == item["sha256"]

    class Pack:
        def attach(self, case_id, body, meta):
            assert case_id == 25
            assert meta["original_event_count"] == 1
            assert meta["file_tags"].endswith("generic-client-info")
            with zipfile.ZipFile(io.BytesIO(body)) as archive:
                assert json.loads(archive.read("velociraptor/results.json")) == rows
                stored = json.loads(archive.read("velociraptor/collection.json"))
                assert stored["asset_id"] == 42
            return {"file_id": 99, "evidence_id": 7}
    result = vr.collect_and_attach(25, CLIENT, pack=Pack(), collector=client, asset_id=42)
    assert result["evidence_id"] == 7 and result["flow_id"] == FLOW
    assert result["asset_id"] == 42


def test_flow_must_be_finished(api_config):
    def run(command, **kwargs):
        query = command[-1]
        if "clients()" in query:
            return completed([{"client_id": CLIENT}])
        if "Artifact.Server.Utils.CollectClient" in query:
            return completed([{"Param": "Hostname"}])
        return completed([{"session_id": FLOW, "state": "ERROR"}])
    client = collector(api_config, run)
    with pytest.raises(vr.VelociraptorError, match="did not finish"):
        client.collect(CLIENT)
