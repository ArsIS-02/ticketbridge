#!/usr/bin/env python3
"""Propagate Zabbix metadata through Graylog aggregation rules safely.

Aggregation makes only group_by fields available to field_spec templates.
Read-only by default. --apply preserves IDs, notifications, key_spec and query,
writes private backups and verifies both PROBLEM and RESOLVED definitions.
Requires GRAYLOG_URL and GRAYLOG_TOKEN.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path

from sync_graylog_iris import Graylog, private_dump

RULES = {
    "6af4adea61b983feab70d037": "ZABBIX - Проблема на узле или сервисе",
    "6af4b20861b983feab70ed30": "ZABBIX - Проблема устранена (RESOLVED)",
}
FIELDS = {
    "event": "${source.zabbix_trigger_description}",
    "host": "${source.source}",
    "zabbix_event_id": "${source.zabbix_event_id}",
    "zabbix_event_status": "${source.zabbix_event_status}",
    "zabbix_trigger_id": "${source.zabbix_trigger_id}",
    "zabbix_severity": "${source.zabbix_severity}",
    "zabbix_nseverity": "${source.zabbix_nseverity}",
    "zabbix_trigger_name": "${source.zabbix_trigger_name}",
    "zabbix_trigger_description": "${source.zabbix_trigger_description}",
    "zabbix_event_duration": "${source.zabbix_event_duration}",
    "zabbix_tags_json": "${source.zabbix_tags_json}",
    "zabbix_url": "${source.zabbix_url}",
    "zabbix_host_conn": "${source.zabbix_host_conn}",
}
GROUP_FIELDS = [
    "zabbix_event_id", "source", "zabbix_event_status", "zabbix_trigger_id",
    "zabbix_severity", "zabbix_nseverity", "zabbix_trigger_name", "zabbix_trigger_description",
    "zabbix_event_duration", "zabbix_tags_json", "zabbix_url", "zabbix_host_conn",
]


def template(value: str) -> dict:
    return {"data_type": "string", "providers": [{
        "type": "template-v1", "template": value,
        "require_values": False, "exclude_empty_fields": True,
    }]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    api = Graylog(os.environ["GRAYLOG_URL"], os.environ["GRAYLOG_TOKEN"])
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results = []
    for rule_id, expected_title in RULES.items():
        current = api.request("GET", f"/api/events/definitions/{rule_id}")
        if current.get("title") != expected_title:
            raise RuntimeError(f"Unexpected event definition {rule_id}; refusing to update")
        before_fields = dict(current.get("field_spec") or {})
        desired_fields = dict(before_fields)
        for name, source in FIELDS.items():
            desired_fields[name] = template(source)
        before_group = list(current["config"].get("group_by") or [])
        desired_group = list(dict.fromkeys(before_group + GROUP_FIELDS))
        missing_fields = sorted(set(FIELDS) - set(before_fields))
        missing_group = sorted(set(desired_group) - set(before_group))
        changed = desired_fields != before_fields or desired_group != before_group
        results.append({"rule_id": rule_id, "missing_fields": missing_fields,
                        "missing_group_fields": missing_group, "changed": changed})
        if not args.apply or not changed:
            continue
        backup = Path.home() / "ticketbridge" / "backups" / f"zabbix-fields-{rule_id}-{stamp}.json"
        private_dump(backup, current)
        entity = {key: value for key, value in current.items()
                  if key not in {"_scope", "matched_at", "updated_at", "scheduler"}}
        entity["field_spec"] = desired_fields
        entity["config"] = dict(current["config"], group_by=desired_group)
        api.request("PUT", f"/api/events/definitions/{rule_id}", entity)
        verify = api.request("GET", f"/api/events/definitions/{rule_id}")
        assert all(name in (verify.get("field_spec") or {}) for name in FIELDS)
        assert set(GROUP_FIELDS).issubset(set(verify["config"].get("group_by") or []))
        assert verify.get("notifications") == current.get("notifications")
        assert verify.get("key_spec") == current.get("key_spec")
        assert verify["config"].get("query") == current["config"].get("query")
        assert verify["id"] == rule_id
        results[-1].update({"status": "verified", "backup": str(backup)})
    print(json.dumps({"mode": "apply" if args.apply else "dry-run", "rules": results},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
