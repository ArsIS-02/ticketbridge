#!/usr/bin/env python3
"""Evaluate opt-in automatic triage without scheduling any collection.

Offline example:
  TB_VR_AUTO_TRIAGE=dry_run python3 tools/auto_triage_dry_run.py \
    --event event.json --clients clients.json --rules event-definition-id

Live resolver example (the sole network operation is read-only clients()):
  TB_VR_AUTO_TRIAGE=dry_run python3 tools/auto_triage_dry_run.py \
    --event event.json --live-clients --rules event-definition-id
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auto_triage import AutoTriagePolicy, build_auto_plan, plan_from_environment
from collection_playbooks import PlaybookRegistry


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", required=True, help="Graylog event JSON")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--clients", help="Offline Velociraptor clients JSON")
    source.add_argument("--live-clients", action="store_true",
                        help="Read-only clients() query; never starts collection")
    parser.add_argument("--rules",
                        help="Comma-separated exact event_definition_id opt-in list")
    parser.add_argument("--registry", help="collection_playbooks.json")
    parser.add_argument("--output", help="Write plan with mode 0600")
    args = parser.parse_args()

    env = dict(os.environ)
    if args.rules is not None:
        env["TB_VR_AUTO_TRIAGE_RULES"] = args.rules
    registry = PlaybookRegistry.load(args.registry) if args.registry else PlaybookRegistry.load()
    event = read_json(args.event)

    if args.live_clients:
        plan = plan_from_environment(event, env, registry=registry)
    else:
        clients_data = read_json(args.clients)
        clients = clients_data.get("items", []) if isinstance(clients_data, dict) else clients_data
        plan = build_auto_plan(
            event, clients, AutoTriagePolicy.from_env(env), registry=registry,
            now=datetime.now(timezone.utc))

    text = json.dumps(plan, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        output = Path(args.output)
        output.write_text(text, encoding="utf-8")
        output.chmod(0o600)
    print(text, end="")
    auto = plan.get("auto_triage") or {}
    return 0 if plan.get("status") == "dry_run" and auto.get("eligible") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
