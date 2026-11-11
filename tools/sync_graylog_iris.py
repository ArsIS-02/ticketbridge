#!/usr/bin/env python3
"""Attach the existing TicketBridge notification to every enabled Graylog alert.

Run with GRAYLOG_URL and GRAYLOG_TOKEN in the environment. The default mode is
a read-only dry run. --apply writes a private JSON backup before changing any
definition, updates only missing notification bindings and verifies the result.
Disabled definitions and definitions with alert=false are never changed.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.request

NOTIFICATION_TITLE = "GLPI Ticket (TicketBridge)"


class Graylog:
    def __init__(self, url: str, token: str):
        self.base = url.rstrip("/")
        self.token = token
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def request(self, method: str, path: str, body=None):
        data = None if body is None else json.dumps(body, ensure_ascii=False).encode()
        request = urllib.request.Request(self.base + path, data=data, method=method)
        request.add_header("Accept", "application/json")
        request.add_header("X-Requested-By", "ticketbridge-iris-sync")
        auth = base64.b64encode((self.token + ":token").encode()).decode()
        request.add_header("Authorization", "Basic " + auth)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, context=self.ctx, timeout=45) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")[:500]
            raise RuntimeError(f"{method} {path}: HTTP {error.code}: {detail}") from error
        return json.loads(raw) if raw.strip() else {}

    def page(self, path: str, key: str):
        result = []
        page = 1
        while True:
            separator = "&" if "?" in path else "?"
            body = self.request("GET", f"{path}{separator}per_page=100&page={page}")
            chunk = body.get(key, [])
            result.extend(chunk)
            if not chunk or len(result) >= body.get("total", len(result)):
                return result
            page += 1


def binding_ids(definition: dict):
    return {item.get("notification_id") for item in definition.get("notifications") or []}


def targets(definitions: list[dict], notification_id: str):
    """Enabled alert-producing definitions missing the TicketBridge binding."""
    return [definition for definition in definitions
            if definition.get("state") == "ENABLED"
            and definition.get("alert") is True
            and notification_id not in binding_ids(definition)]


def update_entity(definition: dict, notification_id: str):
    # Read-only metadata returned by Graylog is not sent back to the update API.
    entity = {key: value for key, value in definition.items()
              if key not in {"_scope", "matched_at", "updated_at", "scheduler"}}
    entity["notifications"] = list(definition.get("notifications") or []) + [
        {"notification_id": notification_id, "notification_parameters": None}
    ]
    return entity


def private_dump(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="apply missing bindings")
    parser.add_argument("--only-id", help="change just one definition (pilot run)")
    args = parser.parse_args()
    url = os.environ.get("GRAYLOG_URL", "")
    token = os.environ.get("GRAYLOG_TOKEN", "")
    if not url or not token:
        raise SystemExit("Set GRAYLOG_URL and GRAYLOG_TOKEN")

    api = Graylog(url, token)
    notifications = api.page("/api/events/notifications", "notifications")
    matching = [item for item in notifications if item.get("title") == NOTIFICATION_TITLE]
    if len(matching) != 1:
        raise SystemExit(f"Expected one {NOTIFICATION_TITLE!r} notification, found {len(matching)}")
    notification_id = matching[0]["id"]
    definitions = api.page("/api/events/definitions", "event_definitions")
    enabled_alerts = [item for item in definitions
                      if item.get("state") == "ENABLED" and item.get("alert") is True]
    selected = targets(definitions, notification_id)
    if args.only_id:
        selected = [item for item in selected if item.get("id") == args.only_id]
        if len(selected) != 1:
            raise SystemExit(f"Definition {args.only_id} is not an eligible missing binding")

    print(f"Enabled alert definitions: {len(enabled_alerts)}")
    print(f"Already bound to TicketBridge: {len(enabled_alerts) - len(targets(definitions, notification_id))}")
    print(f"Selected for update: {len(selected)}")
    print("Selected priorities:", dict(sorted(Counter(item.get("priority") for item in selected).items())))
    for item in selected:
        print(f"{'APPLY' if args.apply else 'DRY-RUN'} | p{item.get('priority')} | "
              f"{item.get('id')} | {item.get('title')}")
    if not args.apply:
        print("No Graylog objects changed. Re-run with --apply after reviewing the list.")
        return

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = Path.home() / "ticketbridge" / "backups" / f"iris-all-alerts-{stamp}"
    backup.mkdir(parents=True, mode=0o700, exist_ok=False)
    private_dump(backup / "notifications-before.json", notifications)
    private_dump(backup / "definitions-before.json", definitions)
    print("Backup:", backup)

    for item in selected:
        definition_id = item["id"]
        # Re-read immediately before writing so concurrent edits are preserved.
        current = api.request("GET", f"/api/events/definitions/{definition_id}")
        if notification_id in binding_ids(current):
            continue
        entity = update_entity(current, notification_id)
        api.request("PUT", f"/api/events/definitions/{definition_id}", entity)
        verify = api.request("GET", f"/api/events/definitions/{definition_id}")
        if notification_id not in binding_ids(verify):
            raise RuntimeError(f"Binding verification failed: {definition_id}")

    final_definitions = api.page("/api/events/definitions", "event_definitions")
    remaining = targets(final_definitions, notification_id)
    if args.only_id:
        remaining = [item for item in remaining if item.get("id") == args.only_id]
    if remaining:
        raise RuntimeError(f"Unverified definitions remain: {len(remaining)}")
    private_dump(backup / "definitions-after.json", final_definitions)
    print(f"Verified new bindings: {len(selected)}")
    final_enabled = [item for item in final_definitions
                     if item.get("state") == "ENABLED" and item.get("alert") is True]
    print(f"Enabled alerts now bound: {len(final_enabled) - len(targets(final_definitions, notification_id))}/{len(final_enabled)}")


if __name__ == "__main__":
    main()
