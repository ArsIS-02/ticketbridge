#!/usr/bin/env python3
"""Fail-closed automatic-triage policy for Graylog → Velociraptor.

The only live operation in this module is the read-only clients() resolver query.
This module never schedules an artifact, creates a Flow or attaches Evidence.
Execution is delegated to auto_triage_hook and remains disabled by default.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os

from collection_playbooks import PlaybookRegistry, build_dry_run
from velociraptor_evidence import VelociraptorCollector

CLIENTS_VQL = "SELECT client_id, last_seen_at, os_info FROM clients()"
SUPPORTED_MODES = {"off", "dry_run", "on"}


@dataclass(frozen=True)
class AutoTriagePolicy:
    mode: str = "off"
    opted_in_rules: frozenset = frozenset()

    @classmethod
    def from_env(cls, environ):
        mode = str(environ.get("TB_VR_AUTO_TRIAGE", "off")).strip().lower() or "off"
        rules = frozenset(
            item.strip() for item in
            str(environ.get("TB_VR_AUTO_TRIAGE_RULES", "")).split(",")
            if item.strip())
        return cls(mode=mode, opted_in_rules=rules)


def _execution_block():
    return {"authorized": False, "requires_confirmation": True, "flow_created": False}


def _auto_block(policy, opted_in, eligible=False, blocking_reasons=None):
    return {
        "mode": policy.mode,
        "opted_in": opted_in,
        "eligible": eligible,
        "blocking_reasons": blocking_reasons or [],
        "kill_switch": policy.mode == "off",
    }


def _failure(status, message, policy, opted_in=False, details=None):
    return {
        "status": status,
        "error": message,
        "details": details or {},
        "auto_triage": _auto_block(policy, opted_in, blocking_reasons=[status]),
        "execution": _execution_block(),
    }


def _precheck(event, policy):
    """Reject disabled, invalid and non-opted-in events before any resolver call."""
    rule_id = str(event.get("event_definition_id") or "")
    opted_in = rule_id in policy.opted_in_rules
    if policy.mode == "off":
        return _failure("disabled", "Automatic triage is disabled", policy, opted_in)
    if policy.mode not in SUPPORTED_MODES:
        return _failure(
            "config_error", "TB_VR_AUTO_TRIAGE supports only off, dry_run and on",
            policy, opted_in, {"mode": policy.mode})
    if not opted_in:
        return _failure(
            "rule_not_opted_in", "event_definition_id is not explicitly opted in",
            policy, False, {"event_definition_id": rule_id})
    return None


def build_auto_plan(event, clients, policy, registry=None, primary_asset=None,
                    hostdeck_assets=None, now=None, context=None):
    """Build a non-executable plan and add strict automatic-eligibility checks."""
    rejected = _precheck(event, policy)
    if rejected:
        return rejected

    plan = build_dry_run(
        event, clients, registry=registry, primary_asset=primary_asset,
        hostdeck_assets=hostdeck_assets, now=now, context=context)
    reasons = []
    if plan.get("status") != "dry_run":
        reasons.append(str(plan.get("status") or "plan_error"))

    client = plan.get("client") or {}
    online = client.get("online_within_configured_threshold")
    if online is False:
        reasons.append("client_offline")
    elif online is None:
        reasons.append("client_last_seen_unknown")

    artifacts = plan.get("artifacts") or []
    if not artifacts:
        reasons.append("no_artifacts")
    if any(artifact.get("upload") is not False for artifact in artifacts):
        reasons.append("artifact_upload_enabled")

    expected_execution = _execution_block()
    if plan.get("execution") != expected_execution:
        reasons.append("execution_not_locked")
    plan["execution"] = expected_execution
    plan["auto_triage"] = _auto_block(
        policy, opted_in=True, eligible=not reasons, blocking_reasons=reasons)
    return plan


def plan_from_environment(event, environ=None, collector=None, registry=None, now=None,
                          primary_asset=None, hostdeck_assets=None, context=None):
    """Resolve clients only for an opted-in plan; this function never collects."""
    env = os.environ if environ is None else environ
    policy = AutoTriagePolicy.from_env(env)
    rejected = _precheck(event, policy)
    if rejected:
        return rejected

    registry = registry or PlaybookRegistry.load()
    rule = registry.rules.get(str(event.get("event_definition_id") or ""))
    if not rule or rule.get("decision", "collect") != "collect":
        # Unknown, disabled and explicitly non-endpoint rules do not even resolve clients.
        return build_auto_plan(
            event, [], policy, registry=registry, primary_asset=primary_asset,
            hostdeck_assets=hostdeck_assets, now=now, context=context)

    try:
        collector = collector or VelociraptorCollector(
            binary=env.get("TB_VR_BINARY", "/opt/velociraptor/velociraptor"),
            api_config=env.get("TB_VR_API_CONFIG", ""),
            gui_url=env.get("TB_VR_GUI_URL", "https://velociraptor.example.test"),
            creator=env.get("TB_VR_CREATOR", "ticketbridge-collector"),
            timeout=int(env.get("TB_VR_TIMEOUT", "300")),
        )
        clients = collector.query(CLIENTS_VQL, timeout=30)
        if not isinstance(clients, list):
            raise ValueError("Client resolver returned a non-list result")
    except Exception as error:
        return _failure(
            "resolver_error", "Read-only Velociraptor client resolution failed",
            policy, True, {"exception": type(error).__name__})

    return build_auto_plan(
        event, clients, policy, registry=registry,
        primary_asset=primary_asset, hostdeck_assets=hostdeck_assets,
        now=now or datetime.now(timezone.utc), context=context)
