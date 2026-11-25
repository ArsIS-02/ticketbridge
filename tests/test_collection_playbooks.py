from datetime import datetime, timezone
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import collection_playbooks as cp

RULE = "test-linux-process"
NOW = datetime(2026, 11, 22, 5, 0, tzinfo=timezone.utc)


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


def client(client_id="C.0000000000000001", hostname="server-01.example.test",
           fqdn="other-name.example.test", system="linux", last_seen=None):
    return {"client_id": client_id,
            "last_seen_at": last_seen if last_seen is not None else int(NOW.timestamp() * 1_000_000),
            "os_info": {"hostname": hostname, "fqdn": fqdn, "system": system}}


def event(host="server-01"):
    return {"id": "event-1", "event_definition_id": RULE,
            "timestamp": "2026-11-22T04:30:00Z", "message": "Test process rule",
            "fields": {"host": host, "exe": "/usr/bin/socat",
                       "src_ip": "192.0.2.10", "dst_port": "443", "user": "test-user"}}


def test_default_registry_is_dry_run_only():
    default = cp.PlaybookRegistry.load()
    assert default.data["status"] == "dry_run_only"
    assert default.rules["6ad30ab9cc18050c4f1d7dbf"]["playbook"] == "linux_process"


def test_registry_rejects_unapproved_builder():
    data = registry().data
    data["playbooks"]["linux_process"]["artifacts"][0]["parameter_builder"] = "arbitrary_vql"
    with pytest.raises(cp.PlaybookError, match="builder"):
        cp.PlaybookRegistry(data)


def test_successful_plan_matches_hostname_not_only_fqdn():
    plan = cp.build_dry_run(event(), [client()], registry=registry(), now=NOW,
                            context={"case_id": 53})
    assert plan["status"] == "dry_run"
    assert plan["client"]["client_id"] == "C.0000000000000001"
    assert plan["client"]["hostname"] == "server-01.example.test"
    assert plan["client"]["fqdn"] == "other-name.example.test"
    assert plan["context"] == {"case_id": 53}
    assert plan["execution"] == {
        "authorized": False, "requires_confirmation": True, "flow_created": False}
    assert [a["name"] for a in plan["artifacts"]] == [
        "Generic.Client.Info", "Linux.Sys.Pslist", "Linux.Network.NetstatEnriched"]
    assert all(a["upload"] is False for a in plan["artifacts"])


def test_unknown_rule_needs_review_without_generic_collection():
    item = event()
    item["event_definition_id"] = "new-unknown-rule"
    plan = cp.build_dry_run(item, [client()], registry=registry(), now=NOW)
    assert plan["status"] == "needs_review"
    assert "artifacts" not in plan and plan["execution"]["authorized"] is False


def test_ioc_and_source_ip_do_not_become_target():
    item = event(host="")
    item.pop("source", None)
    item["fields"] = {"src_ip": "192.0.2.10", "dst_ip": "198.51.100.20",
                      "ioc": "203.0.113.80"}
    plan = cp.build_dry_run(item, [client()], registry=registry(), now=NOW)
    assert plan["status"] == "target_missing"
    assert plan["execution"]["flow_created"] is False


def test_hostdeck_can_map_target_ip_to_managed_hostname():
    item = event(host="192.0.2.10")
    plan = cp.build_dry_run(
        item, [client()], registry=registry(), now=NOW,
        hostdeck_assets=[{"name": "server-01.example.test", "ip": "192.0.2.10"}])
    assert plan["status"] == "dry_run"
    assert plan["target_candidates"][1]["source"] == "hostdeck:fields.host"


def test_unknown_host_fails_closed():
    plan = cp.build_dry_run(event("unknown"), [client()], registry=registry(), now=NOW)
    assert plan["status"] == "client_not_found"


def test_duplicate_short_hostname_is_ambiguous():
    other = client("C.0000000000000002", "server-01.other.test", "server-01.other.test")
    plan = cp.build_dry_run(event(), [client(), other], registry=registry(), now=NOW)
    assert plan["status"] == "client_ambiguous"
    assert len(plan["details"]["client_ids"]) == 2


@pytest.mark.parametrize("asset_name,hostname,fqdn", [
    ("wazuh.homelab.monitoring.test", "wazuh-homelab.monitoring.test",
     "wazuh-homelab.monitoring.test"),
    ("MacBookPro", "MacBook-Pro", "MacBook-Pro"),
])
def test_normalized_hostname_separators_match_one_client(asset_name, hostname, fqdn):
    plan = cp.build_dry_run(event(asset_name), [client(hostname=hostname, fqdn=fqdn)],
                            registry=registry(), now=NOW)
    assert plan["status"] == "dry_run"
    assert plan["client"]["client_id"] == "C.0000000000000001"


def test_normalized_separator_collision_is_ambiguous():
    other = client("C.0000000000000002", "server01.other.test", "server01.other.test")
    plan = cp.build_dry_run(event("server-01"), [client(), other],
                            registry=registry(), now=NOW)
    assert plan["status"] == "client_ambiguous"
    assert len(plan["details"]["client_ids"]) == 2


def test_different_candidates_for_two_clients_are_ambiguous():
    item = event("server-01")
    item["source"] = "server-02.example.test"
    other = client("C.0000000000000002", "server-02.example.test", "server-02.example.test")
    plan = cp.build_dry_run(item, [client(), other], registry=registry(), now=NOW)
    assert plan["status"] == "client_ambiguous"


def test_platform_mismatch_fails_closed():
    plan = cp.build_dry_run(event(), [client(system="windows")], registry=registry(), now=NOW)
    assert plan["status"] == "platform_mismatch"


def test_primary_iris_asset_is_fallback():
    item = event(host="")
    item["fields"] = {}
    plan = cp.build_dry_run(item, [client()], registry=registry(), now=NOW,
                            primary_asset={"asset_name": "server-01.example.test"})
    assert plan["status"] == "dry_run"
    assert plan["target_candidates"][0]["source"] == "iris.primary_asset"


def test_parameters_are_literal_and_typed():
    item = event()
    item["fields"]["exe"] = "/tmp/a+b[1]"
    plan = cp.build_dry_run(item, [client()], registry=registry(), now=NOW)
    pslist = plan["artifacts"][1]["parameters"]
    netstat = plan["artifacts"][2]["parameters"]
    assert pslist == {"processRegex": r"a\+b\[1\]"}
    assert netstat["IPRegex"] == "192\\.0\\.2\\.10"
    assert netstat["PortRegex"] == "443"
    assert netstat["UsernameRegex"] == "test\\-user"
    assert netstat["ConnectionStatusRegex"] == "LISTEN|ESTAB"
    assert "VQL" not in json.dumps(plan)


def test_invalid_ip_and_port_filters_are_ignored_with_warning():
    item = event()
    item["fields"].update({"src_ip": "not-an-ip", "dst_port": "70000"})
    plan = cp.build_dry_run(item, [client()], registry=registry(), now=NOW)
    netstat = plan["artifacts"][2]["parameters"]
    assert netstat["IPRegex"] == "." and netstat["PortRegex"] == "."
    assert any("invalid IP" in warning for warning in plan["warnings"])
    assert any("invalid port" in warning for warning in plan["warnings"])


def test_overlong_process_filter_is_not_interpolated():
    item = event()
    item["fields"]["exe"] = "/tmp/" + "x" * 200
    plan = cp.build_dry_run(item, [client()], registry=registry(), now=NOW)
    assert plan["artifacts"][1]["parameters"]["processRegex"] == "."
    assert any("overlong" in warning for warning in plan["warnings"])


def test_event_window_is_bounded():
    plan = cp.build_dry_run(event(), [client()], registry=registry(), now=NOW)
    assert plan["time_window"] == {
        "start": "2026-11-22T04:15:00.000Z", "end": "2026-11-22T04:45:00.000Z"}


def test_invalid_timestamp_produces_warning_not_current_time_query():
    item = event()
    item["timestamp"] = "not-a-time"
    plan = cp.build_dry_run(item, [client()], registry=registry(), now=NOW)
    assert plan["time_window"] is None
    assert any("timestamp" in warning for warning in plan["warnings"])


def test_stale_client_is_reported_but_never_auto_authorized():
    stale = int((NOW.timestamp() - 3600) * 1_000_000)
    plan = cp.build_dry_run(event(), [client(last_seen=stale)], registry=registry(), now=NOW)
    assert plan["client"]["online_within_configured_threshold"] is False
    assert plan["client"]["last_seen_age_seconds"] == 3600
    assert plan["execution"] == {
        "authorized": False, "requires_confirmation": True, "flow_created": False}


def test_missing_last_seen_is_explicit():
    plan = cp.build_dry_run(event(), [client(last_seen="")], registry=registry(), now=NOW)
    assert plan["client"]["online_within_configured_threshold"] is None
    assert any("last_seen" in warning for warning in plan["warnings"])


def test_unix_timestamp_units():
    value = 1_795_324_246
    assert cp._unix_seconds(value) == value
    assert cp._unix_seconds(value * 1_000) == value
    assert cp._unix_seconds(value * 1_000_000) == value
    assert cp._unix_seconds(value * 1_000_000_000) == value
    assert cp._unix_seconds("bad") is None
