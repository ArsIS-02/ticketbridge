#!/usr/bin/env python3
"""Make IRIS the primary instant-mail sender without disabling Graylog digests.

Run with GRAYLOG_URL and GRAYLOG_TOKEN in the environment. The default mode is
a read-only dry run. --apply writes a private JSON backup, removes only instant
email bindings from enabled TicketBridge-backed alerts and verifies every rule.
Disabled definitions, alert=false, TicketBridge itself and digest mail are kept.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import os
from pathlib import Path

from sync_graylog_iris import Graylog
from sync_graylog_iris import binding_ids
from sync_graylog_iris import private_dump

NOTIFICATION_TITLE = "GLPI Ticket (TicketBridge)"
READ_ONLY_FIELDS = {"_scope", "matched_at", "updated_at", "scheduler"}


def instant_mail_ids(notifications: list[dict]) -> set[str]:
    """Instant alert mail only; daily/morning digests remain in Graylog."""
    return {
        item["id"] for item in notifications
        if (item.get("config") or {}).get("type") == "email-notification-v1"
        and "digest" not in (item.get("title") or "").lower()
    }


def targets(definitions: list[dict], mail_ids: set[str], hook_id: str):
    """Enabled IRIS-backed alerts that still have instant Graylog mail."""
    result = []
    for definition in definitions:
        ids = binding_ids(definition)
        if (definition.get("state") == "ENABLED"
                and definition.get("alert") is True
                and hook_id in ids and ids & mail_ids):
            result.append(definition)
    return result


def update_entity(definition: dict, mail_ids: set[str], hook_id: str):
    if hook_id not in binding_ids(definition):
        raise RuntimeError(f"TicketBridge binding disappeared: {definition.get('id')}")
    entity = {key: value for key, value in definition.items()
              if key not in READ_ONLY_FIELDS}
    entity["notifications"] = [
        item for item in definition.get("notifications") or []
        if item.get("notification_id") not in mail_ids
    ]
    return entity


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="remove duplicate instant mail")
    parser.add_argument("--only-id", help="change just one definition (pilot run)")
    args = parser.parse_args()
    url = os.environ.get("GRAYLOG_URL", "")
    token = os.environ.get("GRAYLOG_TOKEN", "")
    if not url or not token:
        raise SystemExit("Set GRAYLOG_URL and GRAYLOG_TOKEN")

    api = Graylog(url, token)
    notifications = api.page("/api/events/notifications", "notifications")
    hooks = [item for item in notifications if item.get("title") == NOTIFICATION_TITLE]
    if len(hooks) != 1:
        raise SystemExit(f"Expected one {NOTIFICATION_TITLE!r} notification, found {len(hooks)}")
    hook_id = hooks[0]["id"]
    mail_ids = instant_mail_ids(notifications)
    titles = {item["id"]: item.get("title") or item["id"] for item in notifications}
    definitions = api.page("/api/events/definitions", "event_definitions")
    selected = targets(definitions, mail_ids, hook_id)
    if args.only_id:
        selected = [item for item in selected if item.get("id") == args.only_id]
        if len(selected) != 1:
            raise SystemExit(f"Definition {args.only_id} is not an eligible duplicate-mail binding")

    counts = Counter(
        titles[notification_id]
        for item in selected
        for notification_id in binding_ids(item) & mail_ids
    )
    print(f"Instant Graylog mail notifications: {len(mail_ids)}")
    print(f"Enabled TicketBridge-backed rules with duplicate mail: {len(targets(definitions, mail_ids, hook_id))}")
    print(f"Selected for update: {len(selected)}")
    print("Bindings by notification:", dict(sorted(counts.items())))
    for item in selected:
        removed = [titles[notification_id]
                   for notification_id in binding_ids(item) & mail_ids]
        print(f"{'APPLY' if args.apply else 'DRY-RUN'} | p{item.get('priority')} | "
              f"{item.get('id')} | {item.get('title')} | detach: {', '.join(removed)}")
    if not args.apply:
        print("No Graylog objects changed. Re-run with --apply after reviewing the list.")
        return

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = Path.home() / "ticketbridge" / "backups" / f"iris-mail-primary-{stamp}"
    backup.mkdir(parents=True, mode=0o700, exist_ok=False)
    private_dump(backup / "notifications-before.json", notifications)
    private_dump(backup / "definitions-before.json", definitions)
    print("Backup:", backup)

    changed = 0
    for item in selected:
        definition_id = item["id"]
        current = api.request("GET", f"/api/events/definitions/{definition_id}")
        ids = binding_ids(current)
        if not (current.get("state") == "ENABLED" and current.get("alert") is True
                and hook_id in ids):
            raise RuntimeError(f"Definition changed concurrently: {definition_id}")
        if not ids & mail_ids:
            continue
        api.request("PUT", f"/api/events/definitions/{definition_id}",
                    update_entity(current, mail_ids, hook_id))
        verify = api.request("GET", f"/api/events/definitions/{definition_id}")
        verify_ids = binding_ids(verify)
        if hook_id not in verify_ids or verify_ids & mail_ids:
            raise RuntimeError(f"Mail detachment verification failed: {definition_id}")
        changed += 1

    final_definitions = api.page("/api/events/definitions", "event_definitions")
    remaining = targets(final_definitions, mail_ids, hook_id)
    if args.only_id:
        remaining = [item for item in remaining if item.get("id") == args.only_id]
    if remaining:
        raise RuntimeError(f"Duplicate instant mail remains: {len(remaining)}")
    private_dump(backup / "definitions-after.json", final_definitions)
    print(f"Verified updated bindings: {changed}")
    print(f"Enabled TicketBridge-backed rules with duplicate mail: {len(targets(final_definitions, mail_ids, hook_id))}")


if __name__ == "__main__":
    main()
