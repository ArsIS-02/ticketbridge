#!/usr/bin/env python3
"""Build a local Velociraptor collection plan without any network or Flow.

Example:
  python tools/velociraptor_dry_run.py --event event.json --clients clients.json \
    --case-id 53 --output dry-run-plan.json
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from collection_playbooks import PlaybookRegistry, build_dry_run


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", required=True, help="Graylog event JSON; no API calls")
    parser.add_argument("--clients", required=True, help="Velociraptor SearchClients JSON")
    parser.add_argument("--registry", help="collection_playbooks.json")
    parser.add_argument("--hostdeck", help="Optional HostDeck assets JSON")
    parser.add_argument("--primary-asset", help="Optional IRIS primary asset name")
    parser.add_argument("--case-id", type=int)
    parser.add_argument("--alert-id", type=int)
    parser.add_argument("--output", help="Write plan with mode 0600")
    args = parser.parse_args()

    registry = PlaybookRegistry.load(args.registry) if args.registry else PlaybookRegistry.load()
    clients_data = read_json(args.clients)
    clients = clients_data.get("items", []) if isinstance(clients_data, dict) else clients_data
    hostdeck_data = read_json(args.hostdeck) if args.hostdeck else []
    if isinstance(hostdeck_data, dict):
        hostdeck_data = hostdeck_data.get("items") or hostdeck_data.get("hosts") or []
    context = {key: value for key, value in
               {"case_id": args.case_id, "alert_id": args.alert_id}.items()
               if value is not None}
    plan = build_dry_run(
        read_json(args.event), clients, registry=registry,
        primary_asset=args.primary_asset, hostdeck_assets=hostdeck_data,
        now=datetime.now(timezone.utc), context=context)
    text = json.dumps(plan, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        output = Path(args.output)
        output.write_text(text, encoding="utf-8")
        output.chmod(0o600)
    print(text, end="")
    return 0 if plan["status"] == "dry_run" else 2


if __name__ == "__main__":
    raise SystemExit(main())
