#!/usr/bin/env python3
"""Execute one explicitly confirmed auto-triage plan and build Evidence ZIP.

This is a separate pilot entry point. It is not connected to Graylog /hook.
Example (real collection; review the dry-run first):
  TB_VR_AUTO_TRIAGE=dry_run python3 tools/auto_triage_execute.py \
    --event event.json --rules event-definition-id --case-id 53 \
    --confirm-event-id exact-graylog-event-id --output-dir ./evidence --attach
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auto_triage import plan_from_environment
from auto_triage_execution import execute_confirmed_plan
from collection_playbooks import PlaybookRegistry
from iris_evidence_pack import EvidencePack
from velociraptor_evidence import VelociraptorCollector


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", required=True, help="Graylog event JSON")
    parser.add_argument("--rules",
                        help="Comma-separated exact event_definition_id opt-in list")
    parser.add_argument("--case-id", required=True, type=int)
    parser.add_argument("--confirm-event-id", required=True,
                        help="Must exactly match event.id in the JSON file")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--registry")
    parser.add_argument("--attach", action="store_true",
                        help="Attach the verified ZIP to IRIS Evidence after collection")
    args = parser.parse_args()

    env = dict(os.environ)
    if args.rules is not None:
        env["TB_VR_AUTO_TRIAGE_RULES"] = args.rules
    registry = PlaybookRegistry.load(args.registry) if args.registry else PlaybookRegistry.load()
    event = json.loads(Path(args.event).read_text(encoding="utf-8"))
    collector = VelociraptorCollector(
        binary=env.get("TB_VR_BINARY", "/opt/velociraptor/velociraptor"),
        api_config=env.get("TB_VR_API_CONFIG", ""),
        gui_url=env.get("TB_VR_GUI_URL", "https://velociraptor.example.test"),
        creator=env.get("TB_VR_CREATOR", "ticketbridge-collector"),
        timeout=int(env.get("TB_VR_TIMEOUT", "300")),
    )
    plan = plan_from_environment(event, env, collector=collector, registry=registry)
    auto = plan.get("auto_triage") or {}
    if plan.get("status") != "dry_run" or auto.get("eligible") is not True:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return 2

    pack = None
    if args.attach:
        pack = EvidencePack(env.get("TB_IRIS_URL", ""), env.get("TB_IRIS_KEY", ""))
    result = execute_confirmed_plan(
        plan, case_id=args.case_id, confirm_event_id=args.confirm_event_id,
        collector=collector, output_dir=args.output_dir, registry=registry, pack=pack)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "completed" and not result["evidence_error"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
