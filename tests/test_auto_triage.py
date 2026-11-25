from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import auto_triage as at
import collection_playbooks as cp

RULE = "test-linux-process"
NOW = datetime(2026, 11, 23, 5, 0, tzinfo=timezone.utc)
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


def event():
    return {
        "id": "synthetic-event", "event_definition_id": RULE,
        "timestamp": "2026-11-23T04:30:00Z", "message": "Synthetic test event",
        "fields": {"host": "server-01", "exe": "/usr/bin/socat"},
    }


def client(last_seen=None):
    return {
        "client_id": "C.0000000000000001",
        "last_seen_at": (last_seen if last_seen is not None
                         else int(NOW.timestamp() * 1_000_000)),
        "os_info": {
            "hostname": "server-01.example.test",
            "fqdn": "server-01.example.test", "system": "linux",
        },
    }


def policy(mode="dry_run", rules=RULE):
    return at.AutoTriagePolicy.from_env({
        "TB_VR_AUTO_TRIAGE": mode,
        "TB_VR_AUTO_TRIAGE_RULES": rules,
    })


class RecordingCollector:
    def __init__(self, clients=None, error=None):
        self.clients = [client()] if clients is None else clients
        self.error = error
        self.calls = []

    def query(self, vql, timeout=None):
        self.calls.append((vql, timeout))
        if self.error:
            raise self.error
        return self.clients


def test_default_off_does_not_construct_collector(monkeypatch):
    monkeypatch.setattr(
        at, "VelociraptorCollector",
        lambda *args, **kwargs: pytest.fail("collector must not be constructed"))
    plan = at.plan_from_environment(event(), {}, registry=registry(), now=NOW)
    assert plan["status"] == "disabled"
    assert plan["auto_triage"] == {
        "mode": "off", "opted_in": False, "eligible": False,
        "blocking_reasons": ["disabled"], "kill_switch": True,
    }
    assert plan["execution"]["flow_created"] is False


def test_missing_opt_in_skips_resolver():
    collector = RecordingCollector()
    plan = at.plan_from_environment(
        event(), {"TB_VR_AUTO_TRIAGE": "dry_run"}, collector=collector,
        registry=registry(), now=NOW)
    assert plan["status"] == "rule_not_opted_in"
    assert plan["auto_triage"]["eligible"] is False
    assert collector.calls == []


@pytest.mark.parametrize("mode", ["1", "enabled"])
def test_execution_modes_are_config_errors_without_resolver(mode):
    collector = RecordingCollector()
    plan = at.plan_from_environment(
        event(), {"TB_VR_AUTO_TRIAGE": mode, "TB_VR_AUTO_TRIAGE_RULES": RULE},
        collector=collector, registry=registry(), now=NOW)
    assert plan["status"] == "config_error"
    assert plan["auto_triage"]["eligible"] is False
    assert collector.calls == []


def test_on_mode_still_only_builds_read_only_plan():
    collector = RecordingCollector()
    plan = at.plan_from_environment(
        event(), {"TB_VR_AUTO_TRIAGE": "on", "TB_VR_AUTO_TRIAGE_RULES": RULE},
        collector=collector, registry=registry(), now=NOW)
    assert plan["status"] == "dry_run"
    assert plan["auto_triage"]["mode"] == "on"
    assert plan["auto_triage"]["eligible"] is True
    assert collector.calls == [(at.CLIENTS_VQL, 30)]
    assert plan["execution"]["flow_created"] is False


def test_eligible_plan_has_three_non_uploaded_artifacts():
    plan = at.build_auto_plan(
        event(), [client()], policy(), registry=registry(), now=NOW)
    assert plan["status"] == "dry_run"
    assert plan["auto_triage"] == {
        "mode": "dry_run", "opted_in": True, "eligible": True,
        "blocking_reasons": [], "kill_switch": False,
    }
    assert [artifact["name"] for artifact in plan["artifacts"]] == ARTIFACTS
    assert all(artifact["upload"] is False for artifact in plan["artifacts"])
    assert plan["execution"] == {
        "authorized": False, "requires_confirmation": True, "flow_created": False}
    assert "CollectClient" not in json.dumps(plan)


def test_stale_client_is_not_eligible():
    stale = int((NOW - timedelta(seconds=3600)).timestamp() * 1_000_000)
    plan = at.build_auto_plan(
        event(), [client(last_seen=stale)], policy(), registry=registry(), now=NOW)
    assert plan["status"] == "dry_run"
    assert plan["auto_triage"]["eligible"] is False
    assert plan["auto_triage"]["blocking_reasons"] == ["client_offline"]
    assert plan["execution"]["flow_created"] is False


def test_unknown_last_seen_is_not_eligible():
    plan = at.build_auto_plan(
        event(), [client(last_seen="")], policy(), registry=registry(), now=NOW)
    assert plan["status"] == "dry_run"
    assert plan["auto_triage"]["eligible"] is False
    assert plan["auto_triage"]["blocking_reasons"] == ["client_last_seen_unknown"]


def test_live_resolver_uses_only_fixed_read_only_query():
    collector = RecordingCollector()
    plan = at.plan_from_environment(
        event(), {"TB_VR_AUTO_TRIAGE": "dry_run", "TB_VR_AUTO_TRIAGE_RULES": RULE},
        collector=collector, registry=registry(), now=NOW)
    assert plan["auto_triage"]["eligible"] is True
    assert collector.calls == [(at.CLIENTS_VQL, 30)]
    assert at.CLIENTS_VQL == "SELECT client_id, last_seen_at, os_info FROM clients()"
    assert "CollectClient" not in collector.calls[0][0]


def test_resolver_error_fails_closed():
    collector = RecordingCollector(error=RuntimeError("sensitive resolver detail"))
    plan = at.plan_from_environment(
        event(), {"TB_VR_AUTO_TRIAGE": "dry_run", "TB_VR_AUTO_TRIAGE_RULES": RULE},
        collector=collector, registry=registry(), now=NOW)
    assert plan["status"] == "resolver_error"
    assert plan["details"] == {"exception": "RuntimeError"}
    assert "sensitive resolver detail" not in json.dumps(plan)
    assert plan["auto_triage"]["eligible"] is False
    assert "artifacts" not in plan
    assert plan["execution"]["flow_created"] is False


def test_unexpected_upload_flag_blocks_eligibility(monkeypatch):
    original = at.build_dry_run

    def unsafe_plan(*args, **kwargs):
        plan = original(*args, **kwargs)
        plan["artifacts"][0]["upload"] = True
        return plan

    monkeypatch.setattr(at, "build_dry_run", unsafe_plan)
    plan = at.build_auto_plan(
        event(), [client()], policy(), registry=registry(), now=NOW)
    assert plan["auto_triage"]["eligible"] is False
    assert "artifact_upload_enabled" in plan["auto_triage"]["blocking_reasons"]


def test_empty_artifact_list_blocks_eligibility(monkeypatch):
    original = at.build_dry_run

    def empty_plan(*args, **kwargs):
        plan = original(*args, **kwargs)
        plan["artifacts"] = []
        return plan

    monkeypatch.setattr(at, "build_dry_run", empty_plan)
    plan = at.build_auto_plan(
        event(), [client()], policy(), registry=registry(), now=NOW)
    assert plan["auto_triage"]["eligible"] is False
    assert "no_artifacts" in plan["auto_triage"]["blocking_reasons"]
