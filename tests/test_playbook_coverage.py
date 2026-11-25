from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import auto_triage as at
import collection_playbooks as cp

NOW = datetime(2026, 11, 23, 5, 0, tzinfo=timezone.utc)
SEEN = int(NOW.timestamp() * 1_000_000)
WINDOW = {"start": "2026-11-23T04:15:00.000Z", "end": "2026-11-23T04:45:00.000Z"}
TIME_BUILDERS = {
    "darwin_authorized_keys", "windows_explicit_logon", "windows_rdp_auth",
    "windows_security_evtx", "windows_log_modifications", "windows_cleared_logs",
    "windows_ps_scriptblock", "windows_ps_module", "windows_recent_docs",
    "windows_prefetch", "windows_task_events",
}


def rule_for(playbook_id, registry=None):
    registry = registry or cp.PlaybookRegistry.load()
    return next(rule_id for rule_id, rule in registry.rules.items()
                if rule.get("playbook") == playbook_id)


def event(rule_id):
    return {
        "id": "synthetic-event", "event_definition_id": rule_id,
        "timestamp": "2026-11-23T04:30:00Z", "message": "Synthetic coverage event",
        "fields": {
            "host": "endpoint-01", "exe": "/tmp/example", "image": "C:\\Temp\\example.exe",
            "process": "example", "user": "test-user", "src_ip": "192.0.2.10",
            "dst_port": "443", "event_id": "4624",
        },
    }


def client(system="linux", client_id="C.0000000000000001", last_seen=SEEN):
    return {
        "client_id": client_id, "last_seen_at": last_seen,
        "os_info": {
            "hostname": "endpoint-01.example.test", "fqdn": "endpoint-01.example.test",
            "system": system,
        },
    }


def test_inventory_covers_every_rule_exactly_once():
    registry = cp.PlaybookRegistry.load()
    assert len(registry.rules) == registry.data["coverage"]["total_rules"] == 272
    assert registry.data["coverage"]["enabled_alert_rules"] == 261
    assert len(set(registry.rules)) == 272
    counts = {decision: sum(rule.get("decision") == decision
                            for rule in registry.rules.values())
              for decision in ("collect", "no_collection", "needs_review")}
    assert counts == {"collect": 189, "no_collection": 69, "needs_review": 14}
    assert sum(rule["state"] == "ENABLED" and rule["alert"] is True
               for rule in registry.rules.values()) == 261


def test_all_playbooks_and_artifacts_are_in_the_installed_snapshot():
    registry = cp.PlaybookRegistry.load()
    assert len(registry.playbooks) == 33
    assert len(registry.data["installed_artifacts"]) == 53
    assert {pb["platform"] for pb in registry.playbooks.values()} == {
        "linux", "darwin", "windows"}
    for playbook in registry.playbooks.values():
        assert playbook["mode"] == "manual"
        assert playbook["timeout_seconds"] <= 600
        assert playbook["row_limit"] <= 10000
        for artifact in playbook["artifacts"]:
            assert artifact["name"] in registry.data["installed_artifacts"]
            assert artifact["name"] in registry.data["artifact_schemas"]


def test_every_collect_rule_builds_a_safe_plan_for_its_own_os():
    registry = cp.PlaybookRegistry.load()
    checked = 0
    for rule_id, rule in registry.rules.items():
        if rule.get("decision") != "collect":
            continue
        playbook = registry.playbooks[rule["playbook"]]
        plan = cp.build_dry_run(
            event(rule_id), [client(playbook["platform"])], registry=registry, now=NOW)
        assert plan["status"] == "dry_run", (rule_id, plan)
        assert plan["playbook"]["id"] == rule["playbook"]
        assert plan["client"]["system"] == playbook["platform"]
        assert plan["client"]["online_within_configured_threshold"] is True
        assert len(plan["artifacts"]) == len(playbook["artifacts"])
        assert plan["execution"] == {
            "authorized": False, "requires_confirmation": True, "flow_created": False}
        assert "CollectClient" not in json.dumps(plan)
        for artifact in plan["artifacts"]:
            assert artifact["upload"] is False
            assert set(artifact["parameters"]) <= set(
                registry.data["artifact_schemas"][artifact["name"]])
            for key, value in artifact["parameters"].items():
                if "upload" in key.lower() or key in {"DumpProcess", "KillProcess"}:
                    assert value is False, (artifact["name"], key, value)
                assert key not in {"Command", "YaraRule", "yaraRule"}
        checked += 1
    assert checked == 189


def test_every_non_collect_rule_stops_before_client_resolution():
    registry = cp.PlaybookRegistry.load()
    checked = 0
    for rule_id, rule in registry.rules.items():
        decision = rule.get("decision")
        if decision == "collect":
            continue
        policy = at.AutoTriagePolicy("dry_run", frozenset({rule_id}))

        class NoResolver:
            def query(self, *args, **kwargs):
                pytest.fail("non-collection rule must not query Velociraptor")

        plan = at.plan_from_environment(
            event(rule_id), {"TB_VR_AUTO_TRIAGE": "dry_run",
                             "TB_VR_AUTO_TRIAGE_RULES": rule_id},
            collector=NoResolver(), registry=registry, now=NOW)
        assert plan["status"] == decision
        assert plan["details"]["reason_code"] == rule["reason_code"]
        assert plan["auto_triage"]["eligible"] is False
        assert decision in plan["auto_triage"]["blocking_reasons"]
        assert "artifacts" not in plan
        assert plan["execution"]["flow_created"] is False
        checked += 1
    assert checked == 83


@pytest.mark.parametrize("playbook_id,system", [
    ("linux_process", "linux"), ("darwin_process", "darwin"),
    ("windows_process", "windows"),
])
def test_offline_and_unknown_last_seen_block_auto_triage_for_every_os(playbook_id, system):
    registry = cp.PlaybookRegistry.load()
    rule_id = rule_for(playbook_id, registry)
    policy = at.AutoTriagePolicy("dry_run", frozenset({rule_id}))
    for last_seen, reason in ((SEEN - 3600 * 1_000_000, "client_offline"),
                              ("", "client_last_seen_unknown")):
        plan = at.build_auto_plan(
            event(rule_id), [client(system, last_seen=last_seen)], policy,
            registry=registry, now=NOW)
        assert plan["status"] == "dry_run"
        assert plan["auto_triage"]["eligible"] is False
        assert reason in plan["auto_triage"]["blocking_reasons"]
        assert plan["execution"]["flow_created"] is False


@pytest.mark.parametrize("playbook_id,system", [
    ("linux_process", "linux"), ("darwin_process", "darwin"),
    ("windows_process", "windows"),
])
def test_ambiguous_and_wrong_os_clients_fail_closed(playbook_id, system):
    registry = cp.PlaybookRegistry.load()
    rule_id = rule_for(playbook_id, registry)
    duplicate = client(system, "C.0000000000000002")
    duplicate["os_info"]["hostname"] = "endpoint-01.other.test"
    duplicate["os_info"]["fqdn"] = "endpoint-01.other.test"
    plan = cp.build_dry_run(
        event(rule_id), [client(system), duplicate], registry=registry, now=NOW)
    assert plan["status"] == "client_ambiguous"

    wrong_system = {"linux": "windows", "windows": "darwin", "darwin": "linux"}[system]
    plan = cp.build_dry_run(
        event(rule_id), [client(wrong_system)], registry=registry, now=NOW)
    assert plan["status"] == "platform_mismatch"
    assert plan["details"]["expected"] == system


@pytest.mark.parametrize("builder", sorted(TIME_BUILDERS))
def test_time_bounded_artifacts_reject_invalid_event_timestamp(builder):
    with pytest.raises(cp.PlaybookError) as caught:
        cp.build_parameters(builder, {"process": "example", "event_id": "4624"}, None)
    assert caught.value.code == "invalid_event_timestamp"


def test_invalid_timestamp_does_not_turn_into_unbounded_log_collection():
    registry = cp.PlaybookRegistry.load()
    rule_id = rule_for("windows_auth", registry)
    item = event(rule_id)
    item["timestamp"] = "not-a-time"
    plan = cp.build_dry_run(item, [client("windows")], registry=registry, now=NOW)
    assert plan["status"] == "invalid_event_timestamp"
    assert "artifacts" not in plan
    assert plan["execution"]["flow_created"] is False


def test_parameter_schema_violation_blocks_the_whole_plan():
    registry = cp.PlaybookRegistry.load()
    data = deepcopy(registry.data)
    rule_id = rule_for("linux_process", registry)
    data["artifact_schemas"]["Linux.Sys.Pslist"] = []
    plan = cp.build_dry_run(
        event(rule_id), [client()], registry=cp.PlaybookRegistry(data), now=NOW)
    assert plan["status"] == "invalid_registry"
    assert plan["details"]["artifact"] == "Linux.Sys.Pslist"
    assert plan["details"]["parameters"] == ["processRegex"]


def test_time_bounded_parameters_use_the_event_window():
    parameters, warnings = cp.build_parameters(
        "windows_security_evtx", {"event_id": "4624, 4625;drop"}, WINDOW)
    assert parameters["StartDate"] == WINDOW["start"]
    assert parameters["EndDate"] == WINDOW["end"]
    assert parameters["IDRegex"] == "4624"  # malformed second value is discarded
    assert warnings == []


def test_windows_remote_access_parameters_cannot_dump_or_kill():
    registry = cp.PlaybookRegistry.load()
    rule_id = rule_for("windows_lateral", registry)
    plan = cp.build_dry_run(event(rule_id), [client("windows")], registry=registry, now=NOW)
    netstat = next(item for item in plan["artifacts"]
                   if item["name"] == "Windows.Network.NetstatEnriched")
    assert netstat["parameters"]["DumpProcess"] is False
    assert netstat["parameters"]["KillProcess"] is False
    assert netstat["parameters"]["DISABLE_DANGEROUS_API_CALLS"] is True


def test_registry_does_not_contain_graylog_queries_or_private_inventory():
    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                assert key not in {"query", "streams", "field_spec", "conditions", "os_info"}
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(cp.PlaybookRegistry.load().data)
