#!/usr/bin/env python3
"""Propagate Wazuh alert fields into Graylog aggregation event fields.

Aggregation makes only group_by fields available to field_spec templates.
Read-only by default. --apply preserves IDs, notifications, key_spec and query,
writes private backups and verifies both definitions.
Requires GRAYLOG_URL and GRAYLOG_TOKEN.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os

from pathlib import Path

from sync_graylog_iris import Graylog, private_dump

RULES = {
    "6af6c5af61b983feab748723": "WAZUH - Важный алерт (уровень 9-11)",
    "6af6c5ae61b983feab74871b": "WAZUH - Критичный алерт (уровень 12+)",
}
FIELDS = {
    "event": "${source.wazuh_rule_desc}",
    "host": "${source.source}",
    "wazuh_agent": "${source.wazuh_agent}",
    "wazuh_rule_desc": "${source.wazuh_rule_desc}",
    "rule_id": "${source.rule_id}",
    "rule_level": "${source.rule_level}",
}
GROUP_FIELDS = ["wazuh_agent", "rule_id", "rule_level", "wazuh_rule_desc", "source"]


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
        group = list(dict.fromkeys(
            list(current["config"].get("group_by") or []) + GROUP_FIELDS))
        missing_fields = [n for n in FIELDS if n not in before_fields]
        missing_group = [n for n in GROUP_FIELDS
                         if n not in (current["config"].get("group_by") or [])]
        changed = bool(missing_fields or missing_group)
        results.append({"rule_id": rule_id, "title": expected_title,
                        "missing_fields": missing_fields,
                        "missing_group_fields": missing_group,
                        "changed": changed})
        if changed and args.apply:
            backup = Path.home() / "ticketbridge" / "backups" / f"wazuh-fields-{rule_id}-{stamp}.json"
            private_dump(backup, current)
            entity = {key: value for key, value in current.items()
                      if key not in {"_scope", "matched_at", "updated_at", "scheduler"}}
            entity["field_spec"] = desired_fields
            entity["config"] = dict(current["config"], group_by=group)
            api.request("PUT", f"/api/events/definitions/{rule_id}", entity)
            verify = api.request("GET", f"/api/events/definitions/{rule_id}")
            assert all(name in (verify.get("field_spec") or {}) for name in FIELDS)
            results[-1]["backup"] = str(backup)
            results[-1]["applied"] = True
    for row in results:
        print(row)


if __name__ == "__main__":
    main()
