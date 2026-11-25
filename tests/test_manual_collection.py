from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import sys
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import manual_collection as mc
import velociraptor_evidence as legacy

CLIENT = "C.0123456789abcdef"
NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)


class FakeCollector:
    creator = "test-collector"
    timeout = 300

    def __init__(self, platform="linux", fail_names=None):
        self.platform = platform
        self.fail_names = set(fail_names or [])
        self.calls = []

    @staticmethod
    def validate_client_id(value):
        return legacy.VelociraptorCollector.validate_client_id(value)

    @staticmethod
    def flow_link(client_id, flow_id):
        return f"https://velociraptor.example.test/{client_id}/{flow_id}"

    def query(self, vql, timeout=None):
        self.calls.append((vql, timeout))
        if "clients()" in vql:
            return [{"client_id": CLIENT, "os_info": {"system": self.platform}}]
        if "Artifact.Server.Utils.CollectClient" in vql:
            name = next(name for name in sorted(mc.ALLOWED_ARTIFACTS, reverse=True)
                        if f"ArtifactName='{name}'" in vql)
            if name in self.fail_names:
                raise RuntimeError("synthetic collection failure")
            return [{"artifact": name, "value": "synthetic-row"}]
        if "FROM flows(" in vql:
            name = next(name for name in sorted(mc.ALLOWED_ARTIFACTS, reverse=True)
                        if f"'{name}' IN request.artifacts" in vql)
            return [{"session_id": "F.TESTFLOW" + str(len(self.calls)),
                     "state": "FINISHED", "create_time": 1_795_000_000_000_000,
                     "total_collected_rows": 1}]
        raise AssertionError("Unexpected VQL: " + vql)


class FakePack:
    def __init__(self):
        self.calls = []

    def attach(self, case_id, content, metadata):
        self.calls.append((case_id, content, metadata))
        return {"evidence_id": 77, "file_id": 88,
                "filename": metadata["filename"], "sha256": metadata["sha256"]}


def verify_zip(content, expected_artifacts):
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        assert archive.testzip() is None
        result_names = [name for name in archive.namelist()
                        if name.startswith("velociraptor/results/")]
        assert len(result_names) == len(expected_artifacts)
        collection = json.loads(archive.read("velociraptor/collection.json"))
        assert [item["artifact"] for item in collection["artifacts"]] == expected_artifacts
        assert all("rows" not in item for item in collection["artifacts"])
        manifest = json.loads(archive.read("manifest.json"))
        for name, item in manifest["files"].items():
            raw = archive.read(name)
            assert len(raw) == item["size"]
            assert hashlib.sha256(raw).hexdigest() == item["sha256"]
        return collection


def test_catalog_is_derived_for_all_platforms():
    catalog = mc.artifact_catalog()
    platforms = {item["id"]: item for item in catalog["platforms"]}
    assert set(platforms) == {"linux", "darwin", "windows"}
    assert len(platforms["linux"]["artifacts"]) == 49
    assert len(platforms["darwin"]["artifacts"]) == 12
    assert len(platforms["windows"]["artifacts"]) == 28
    assert catalog["max_artifacts"] == 8
    darwin = {item["name"] for item in platforms["darwin"]["artifacts"]}
    assert "Linux.Sys.Pslist" in darwin
    assert "Generic.System.HostsFile" in darwin
    assert not any(name.startswith("Custom.Remediation.") for name in mc.ALLOWED_ARTIFACTS)
    for platform, items in platforms.items():
        names = [item["name"] for item in items["artifacts"]]
        assert names == sorted(mc.ARTIFACT_SPECS[platform])
        assert all(item["description"] for item in items["artifacts"])


class ResolverCollector:
    def __init__(self, clients):
        self.clients = clients
        self.calls = []

    def query(self, vql, timeout=None):
        self.calls.append((vql, timeout))
        return self.clients


def resolver_client(client_id=CLIENT, hostname="server-01", fqdn="server-01.example.test",
                    system="linux"):
    return {"client_id": client_id, "last_seen_at": 1,
            "os_info": {"hostname": hostname, "fqdn": fqdn, "system": system}}


def test_hostname_resolver_uses_fixed_read_only_query_and_returns_live_platform():
    collector = ResolverCollector([resolver_client()])
    result = mc.resolve_client_by_hostname(" SERVER-01.EXAMPLE.TEST. ", collector=collector)
    assert result == {"client_id": CLIENT, "hostname": "server-01",
                      "fqdn": "server-01.example.test", "platform": "linux",
                      "matched_by": "iris.asset_name"}
    assert collector.calls == [(
        "SELECT client_id, last_seen_at, os_info FROM clients()", 30)]


def test_hostname_resolver_fails_closed_on_duplicate_short_names():
    collector = ResolverCollector([
        resolver_client(),
        resolver_client("C.0000000000000001", "server-01", "server-01.other.test"),
    ])
    with pytest.raises(Exception, match="More than one") as caught:
        mc.resolve_client_by_hostname("server-01", collector=collector)
    assert caught.value.code == "client_ambiguous"


def test_hostname_resolver_rejects_missing_hostname_before_api_call():
    collector = ResolverCollector([])
    with pytest.raises(mc.ManualCollectionError, match="hostname"):
        mc.resolve_client_by_hostname(" ", collector=collector)
    assert collector.calls == []


@pytest.mark.parametrize("platform,artifacts,message", [
    ("", ["Generic.Client.Info"], "platform"),
    ("linux", [], "at least one"),
    ("linux", ["Generic.Client.Info", "Generic.Client.Info"], "Duplicate"),
    ("linux", ["Windows.System.Pslist"], "not allowed"),
    ("darwin", ["Custom.Remediation.DeleteFile"], "Invalid|not allowed"),
    ("windows", ["Windows.System.Pslist', DELETE"], "Invalid"),
    ("windows", ["Unknown.Artifact"], "Invalid|not allowed"),
])
def test_invalid_selection_is_rejected(platform, artifacts, message):
    with pytest.raises(mc.ManualCollectionError, match=message):
        mc.validate_selection(platform, artifacts)


def test_selection_limit_is_enforced_before_api_calls():
    collector = FakeCollector()
    artifacts = sorted(mc.ARTIFACT_SPECS["linux"])[:mc.MAX_ARTIFACTS + 1]
    with pytest.raises(mc.ManualCollectionError, match="No more than"):
        mc.collect_many(collector, CLIENT, "linux", artifacts)
    assert collector.calls == []


def test_platform_mismatch_is_rejected_before_flow_creation():
    collector = FakeCollector(platform="windows")
    with pytest.raises(mc.ManualCollectionError, match="does not match"):
        mc.collect_many(collector, CLIENT, "linux", ["Generic.Client.Info"])
    assert len(collector.calls) == 1
    assert "clients()" in collector.calls[0][0]


def test_successful_multi_collection_has_one_verified_zip():
    selected = ["Generic.Client.Info", "Linux.Sys.Pslist", "Linux.Network.NetstatEnriched"]
    collector = FakeCollector()
    pack = FakePack()
    result = mc.collect_many_and_attach(
        73, CLIENT, "linux", selected, collector=collector, pack=pack,
        asset_id=1276, now=NOW)
    assert result["status"] == "completed"
    assert result["requested_artifacts"] == selected
    assert result["asset_id"] == 1276
    assert result["evidence_id"] == 77
    assert len(result["artifacts"]) == 3 and result["errors"] == []
    assert len(pack.calls) == 1
    content, metadata = pack.calls[0][1:]
    assert metadata["collection_errors"] == 0
    assert metadata["original_event_count"] == 3
    assert hashlib.sha256(content).hexdigest() == result["sha256"]
    collection = verify_zip(content, selected)
    assert collection["platform"] == "linux"
    assert collection["parameter_window"]["start"].startswith("2026-10-24T12:00:00")
    collect_calls = [vql for vql, _ in collector.calls if "CollectClient" in vql]
    assert len(collect_calls) == 3
    assert all("LIMIT 10000" in vql for vql in collect_calls)


def test_partial_failure_preserves_other_results_and_error_details():
    selected = ["Generic.Client.Info", "Linux.Sys.Pslist", "Linux.Sys.Users"]
    collector = FakeCollector(fail_names={"Linux.Sys.Pslist"})
    pack = FakePack()
    result = mc.collect_many_and_attach(
        73, CLIENT, "linux", selected, collector=collector, pack=pack, now=NOW)
    assert result["status"] == "partial"
    assert [item["artifact"] for item in result["artifacts"]] == [
        "Generic.Client.Info", "Linux.Sys.Users"]
    assert result["errors"][0]["artifact"] == "Linux.Sys.Pslist"
    content, metadata = pack.calls[0][1:]
    assert metadata["collection_errors"] == 1
    verify_zip(content, ["Generic.Client.Info", "Linux.Sys.Users"])
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        errors = json.loads(archive.read("velociraptor/errors.json"))
        assert errors[0]["exception"] == "RuntimeError"


def test_windows_parameters_are_fixed_and_dangerous_actions_disabled():
    selected = ["Windows.Network.NetstatEnriched", "Windows.EventLogs.ExplicitLogon"]
    collector = FakeCollector(platform="windows")
    result = mc.collect_many(collector, CLIENT, "windows", selected, now=NOW)
    assert result["status"] == "completed"
    netstat = next(item for item in result["artifacts"]
                   if item["artifact"] == "Windows.Network.NetstatEnriched")
    assert netstat["parameters"]["DumpProcess"] is False
    assert netstat["parameters"]["KillProcess"] is False
    assert netstat["parameters"]["DISABLE_DANGEROUS_API_CALLS"] is True
    event_log = next(item for item in result["artifacts"]
                     if item["artifact"] == "Windows.EventLogs.ExplicitLogon")
    assert event_log["parameters"]["DateAfter"] == "2026-10-24T12:00:00.000Z"
    assert event_log["parameters"]["DateBefore"] == "2026-11-23T12:05:00.000Z"
    for item in result["artifacts"]:
        assert item["parameter_builder"] in {"windows_netstat", "windows_explicit_logon"}


def test_all_failures_still_create_an_error_pack_with_failed_status():
    collector = FakeCollector(fail_names={"Generic.Client.Info"})
    pack = FakePack()
    result = mc.collect_many_and_attach(
        73, CLIENT, "linux", ["Generic.Client.Info"], collector=collector,
        pack=pack, now=NOW)
    assert result["status"] == "failed"
    assert result["artifacts"] == [] and len(result["errors"]) == 1
    assert len(pack.calls) == 1
    verify_zip(pack.calls[0][1], [])
