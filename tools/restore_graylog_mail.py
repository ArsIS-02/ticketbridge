#!/usr/bin/env python3
"""Restore instant Graylog email bindings from private synchronization backups.

Run with GRAYLOG_URL and GRAYLOG_TOKEN in the environment. The default mode is
a read-only dry run. --apply writes a fresh private backup, restores only missing
instant-mail bindings on enabled TicketBridge-backed alerts and verifies every
rule. Existing bindings, disabled definitions, alert=false and digests are kept.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path

from sync_graylog_iris import Graylog
from sync_graylog_iris import binding_ids
from sync_graylog_iris import private_dump
from sync_graylog_mail import NOTIFICATION_TITLE
from sync_graylog_mail import READ_ONLY_FIELDS
from sync_graylog_mail import instant_mail_ids


def load_saved_bindings(backup_paths: list[Path]) -> dict[str, list[dict]]:
    """Merge saved instant-mail bindings without replacing current definitions."""
    saved: dict[str, dict[str, dict]] = {}
    for backup in backup_paths:
        notifications = json.loads((backup / "notifications-before.json").read_text(encoding="utf-8"))
        definitions = json.loads((backup / "definitions-before.json").read_text(encoding="utf-8"))
        mail_ids = instant_mail_ids(notifications)
        for definition in definitions:
            identifier = definition.get("id")
            if not identifier:
                continue
            target = saved.setdefault(identifier, {})
            for binding in definition.get("notifications") or []:
                notification_id = binding.get("notification_id")
                if notification_id in mail_ids:
                    target.setdefault(notification_id, {
                        "notification_id": notification_id,
                        "notification_parameters": binding.get("notification_parameters"),
                    })
    return {identifier: list(bindings.values()) for identifier, bindings in saved.items()}


def targets(definitions: list[dict], saved: dict[str, list[dict]], hook_id: str) -> list[dict]:
    """Eligible current alerts that are missing at least one saved mail binding."""
    result = []
    for definition in definitions:
        ids = binding_ids(definition)
        missing = [item for item in saved.get(definition.get("id"), [])
                   if item["notification_id"] not in ids]
        if (missing and definition.get("state") == "ENABLED"
                and definition.get("alert") is True and hook_id in ids):
            result.append(definition)
    return result


def update_entity(definition: dict, missing: list[dict], hook_id: str):
    if hook_id not in binding_ids(definition):
        raise RuntimeError(f"TicketBridge binding disappeared: {definition.get('id')}")
    entity = {key: value for key, value in definition.items()
              if key not in READ_ONLY_FIELDS}
    entity["notifications"] = list(definition.get("notifications") or []) + missing
    return entity


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup", action="append", type=Path, required=True,
                        help="private iris-mail-primary backup; repeat for multiple sets")
    parser.add_argument("--apply", action="store_true", help="restore missing instant mail")
    args = parser.parse_args()
    url = os.environ.get("GRAYLOG_URL", "")
    token = os.environ.get("GRAYLOG_TOKEN", "")
    if not url or not token:
        raise SystemExit("Set GRAYLOG_URL and GRAYLOG_TOKEN")

    saved = load_saved_bindings(args.backup)
    api = Graylog(url, token)
    notifications = api.page("/api/events/notifications", "notifications")
    hooks = [item for item in notifications if item.get("title") == NOTIFICATION_TITLE]
    if len(hooks) != 1:
        raise SystemExit(f"Expected one {NOTIFICATION_TITLE!r} notification, found {len(hooks)}")
    hook_id = hooks[0]["id"]
    titles = {item["id"]: item.get("title") or item["id"] for item in notifications}
    definitions = api.page("/api/events/definitions", "event_definitions")
    selected = targets(definitions, saved, hook_id)
    counts = Counter(
        titles.get(item["notification_id"], item["notification_id"])
        for definition in selected
        for item in saved[definition["id"]]
        if item["notification_id"] not in binding_ids(definition)
    )
    print(f"Backup sets: {len(args.backup)}; definitions with saved instant mail: {len(saved)}")
    print(f"Selected for restore: {len(selected)}")
    print("Bindings by notification:", dict(sorted(counts.items())))
    for definition in selected:
        missing = [titles.get(item["notification_id"], item["notification_id"])
                   for item in saved[definition["id"]]
                   if item["notification_id"] not in binding_ids(definition)]
        print(f"{'APPLY' if args.apply else 'DRY-RUN'} | p{definition.get('priority')} | "
              f"{definition.get('id')} | {definition.get('title')} | attach: {', '.join(missing)}")
    if not args.apply:
        print("No Graylog objects changed. Re-run with --apply after reviewing the list.")
        return

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = Path.home() / "ticketbridge" / "backups" / f"graylog-mail-restored-{stamp}"
    backup.mkdir(parents=True, mode=0o700, exist_ok=False)
    private_dump(backup / "notifications-before.json", notifications)
    private_dump(backup / "definitions-before.json", definitions)
    private_dump(backup / "saved-instant-mail.json", saved)
    print("Backup:", backup)

    changed = 0
    restored = 0
    for item in selected:
        definition_id = item["id"]
        current = api.request("GET", f"/api/events/definitions/{definition_id}")
        ids = binding_ids(current)
        if not (current.get("state") == "ENABLED" and current.get("alert") is True
                and hook_id in ids):
            raise RuntimeError(f"Definition changed concurrently: {definition_id}")
        missing = [binding for binding in saved[definition_id]
                   if binding["notification_id"] not in ids]
        if not missing:
            continue
        api.request("PUT", f"/api/events/definitions/{definition_id}",
                    update_entity(current, missing, hook_id))
        verify = api.request("GET", f"/api/events/definitions/{definition_id}")
        verify_ids = binding_ids(verify)
        if hook_id not in verify_ids or not {item["notification_id"] for item in missing} <= verify_ids:
            raise RuntimeError(f"Mail restoration verification failed: {definition_id}")
        changed += 1
        restored += len(missing)

    final_definitions = api.page("/api/events/definitions", "event_definitions")
    remaining = targets(final_definitions, saved, hook_id)
    if remaining:
        raise RuntimeError(f"Saved instant mail still missing: {len(remaining)}")
    private_dump(backup / "definitions-after.json", final_definitions)
    print(f"Verified updated definitions: {changed}; restored bindings: {restored}")
    print(f"Eligible rules still missing saved instant mail: {len(remaining)}")


if __name__ == "__main__":
    main()
