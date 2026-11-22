#!/usr/bin/env python3
"""Dry-run Collection Playbooks for Graylog → Velociraptor.

This module only builds and validates a collection plan. It has no network,
subprocess, Velociraptor CLI or IRIS code and cannot create a Flow.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import re

DEFAULT_REGISTRY = Path(__file__).resolve().with_name("collection_playbooks.json")
_BUILDERS = {"empty", "linux_pslist", "linux_netstat"}
_MAX_PATTERN = 128


class PlaybookError(ValueError):
    def __init__(self, code, message, details=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


class PlaybookRegistry:
    def __init__(self, data):
        if data.get("schema_version") != 1 or data.get("status") != "dry_run_only":
            raise PlaybookError("invalid_registry", "Registry must be schema v1 dry_run_only")
        self.data = data
        self.playbooks = data.get("playbooks") or {}
        self.rules = data.get("rules") or {}
        for playbook_id, playbook in self.playbooks.items():
            artifacts = playbook.get("artifacts") or []
            if not artifacts:
                raise PlaybookError("invalid_registry", f"Empty artifacts: {playbook_id}")
            for artifact in artifacts:
                if artifact.get("parameter_builder") not in _BUILDERS:
                    raise PlaybookError(
                        "invalid_registry", "Unapproved artifact parameter builder",
                        {"playbook": playbook_id, "artifact": artifact.get("name")})
                if artifact.get("parameter_builder") == "empty" and artifact.get("parameters"):
                    raise PlaybookError("invalid_registry", "Unexpected fixed parameters")
        for rule_id, rule in self.rules.items():
            if not rule_id or rule.get("playbook") not in self.playbooks:
                raise PlaybookError("invalid_registry", "Unknown playbook in rule mapping",
                                    {"rule_id": rule_id})

    @classmethod
    def load(cls, path=DEFAULT_REGISTRY):
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def select(self, rule_id):
        rule = self.rules.get(str(rule_id or ""))
        if not rule:
            raise PlaybookError("needs_review", "No approved playbook for event_definition_id",
                                {"event_definition_id": str(rule_id or "")})
        playbook_id = rule["playbook"]
        return playbook_id, self.playbooks[playbook_id], rule


def normalize_name(value):
    """Normalize a hostname for exact matching; never turn it into code."""
    if not isinstance(value, str):
        return ""
    return value.strip().lower().rstrip(".")


def _short_name(value):
    return value.split(".", 1)[0] if value else ""


def _is_ip(value):
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def target_candidates(event, primary_asset=None, hostdeck_assets=None):
    """Return ordered target hints; IOC/source/destination IPs are excluded."""
    fields = event.get("fields") or {}
    raw = []
    for source, value in (
        ("fields.host", fields.get("host")),
        ("fields.host_name", fields.get("host_name")),
        ("event.source", event.get("source")),
        ("iris.primary_asset", primary_asset),
    ):
        if isinstance(value, dict):
            value = value.get("asset_name") or value.get("name")
        if isinstance(value, str) and value.strip():
            raw.append({"value": value.strip(), "source": source})

    # A target IP is useful only if HostDeck proves it is a managed asset.
    assets = hostdeck_assets or []
    for hint in list(raw):
        value = hint["value"]
        if not _is_ip(value):
            continue
        for asset in assets:
            if str(asset.get("ip") or "").strip() == value and asset.get("name"):
                raw.append({"value": str(asset["name"]).strip(),
                            "source": "hostdeck:" + hint["source"]})
                break

    result, seen = [], set()
    for hint in raw:
        key = normalize_name(hint["value"])
        if key and key not in seen:
            seen.add(key)
            result.append(hint)
    return result


def _client_aliases(client):
    os_info = client.get("os_info") or {}
    aliases = set()
    for field in ("hostname", "fqdn"):
        value = normalize_name(os_info.get(field))
        if value:
            aliases.add(value)
            aliases.add(_short_name(value))
    return aliases


def resolve_client(candidates, clients, expected_platform=None):
    """Resolve exactly one client by hostname/FQDN/short name, never by IOC."""
    matches = {}
    evidence = []
    for hint in candidates:
        value = normalize_name(hint.get("value"))
        for client in clients:
            if value and value in _client_aliases(client):
                client_id = str(client.get("client_id") or "")
                if client_id:
                    matches[client_id] = client
                    evidence.append({"candidate": hint, "client_id": client_id})
    if not matches:
        raise PlaybookError("client_not_found", "No unique Velociraptor client matched",
                            {"candidates": candidates})
    if len(matches) != 1:
        raise PlaybookError("client_ambiguous", "More than one Velociraptor client matched",
                            {"client_ids": sorted(matches), "matches": evidence})
    client_id, client = next(iter(matches.items()))
    system = str((client.get("os_info") or {}).get("system") or "").lower()
    if expected_platform and system != expected_platform:
        raise PlaybookError("platform_mismatch", "Client OS does not match playbook",
                            {"client_id": client_id, "expected": expected_platform,
                             "actual": system or "unknown"})
    return client, evidence


def _unix_seconds(value):
    if value in (None, ""):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number > 1e17:       # nanoseconds
        number /= 1e9
    elif number > 1e14:     # microseconds, including Velociraptor last_seen_at
        number /= 1e6
    elif number > 1e11:     # milliseconds
        number /= 1e3
    return number


def _event_window(event, seconds):
    value = event.get("timestamp")
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        moment = moment.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None, "Invalid or missing event timestamp; time window was not built"
    delta = timedelta(seconds=int(seconds))
    def fmt(value):
        return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return {"start": fmt(moment - delta), "end": fmt(moment + delta)}, None


def _literal_pattern(fields, names, basename=False, limit=_MAX_PATTERN):
    for name in names:
        value = fields.get(name)
        if not isinstance(value, str) or not value.strip():
            continue
        value = value.strip()
        if basename:
            value = value.rsplit("/", 1)[-1]
        if len(value) > limit:
            return ".", f"Ignored overlong filter field: {name}"
        return re.escape(value), None
    return ".", None


def _regex_values(fields, names, kind, limit=5):
    values, invalid = [], []
    for name in names:
        value = fields.get(name)
        if not isinstance(value, str) or not value.strip():
            continue
        value = value.strip()
        try:
            if kind == "ip":
                value = str(ipaddress.ip_address(value))
            else:
                port = int(value)
                if not 1 <= port <= 65535:
                    raise ValueError
                value = str(port)
            if value not in values:
                values.append(value)
        except ValueError:
            invalid.append(name)
        if len(values) >= limit:
            break
    return values, invalid


def build_parameters(builder, fields):
    """Build typed artifact parameters without accepting VQL or arbitrary keys."""
    warnings = []
    if builder == "empty":
        return {}, warnings
    process, warning = _literal_pattern(fields, ("process", "comm", "exe"), basename=True)
    if warning:
        warnings.append(warning)
    if builder == "linux_pslist":
        return {"processRegex": process}, warnings
    if builder == "linux_netstat":
        ips, bad_ips = _regex_values(
            fields, ("src_ip", "dst_ip", "dest_ip", "srcip", "dstip"), "ip")
        ports, bad_ports = _regex_values(
            fields, ("dst_port", "dest_port", "port"), "port")
        username, warning = _literal_pattern(fields, ("user", "username"), limit=64)
        if warning:
            warnings.append(warning)
        warnings.extend("Ignored invalid IP filter: " + name for name in bad_ips)
        warnings.extend("Ignored invalid port filter: " + name for name in bad_ports)
        return {
            "IPRegex": "|".join(re.escape(value) for value in ips) or ".",
            "PortRegex": "|".join(ports) or ".",
            "ProcessNameRegex": process,
            "UsernameRegex": username,
            "ConnectionStatusRegex": "LISTEN|ESTAB",
            "ProcessPathRegex": ".",
            "CommandLineRegex": ".",
            "CallChainRegex": ".",
        }, warnings
    raise PlaybookError("invalid_registry", "Unknown parameter builder", {"builder": builder})


def _execution_block():
    return {"authorized": False, "requires_confirmation": True, "flow_created": False}


def _error(code, message, details):
    return {"status": code, "error": message, "details": details,
            "execution": _execution_block()}


def build_dry_run(event, clients, registry=None, primary_asset=None,
                  hostdeck_assets=None, now=None, context=None):
    """Return a non-executable plan; all failures are fail-closed."""
    registry = registry or PlaybookRegistry.load()
    rule_id = str(event.get("event_definition_id") or "")
    try:
        playbook_id, playbook, rule = registry.select(rule_id)
        candidates = target_candidates(event, primary_asset, hostdeck_assets)
        if not candidates:
            raise PlaybookError("target_missing", "No managed target hostname in event")
        client, matches = resolve_client(candidates, clients, playbook.get("platform"))
        warnings = []
        artifacts = []
        for artifact in playbook["artifacts"]:
            parameters, parameter_warnings = build_parameters(
                artifact["parameter_builder"], event.get("fields") or {})
            warnings.extend(parameter_warnings)
            artifacts.append({"name": artifact["name"], "parameters": parameters,
                              "upload": False})
        window, warning = _event_window(event, playbook.get("time_window_seconds", 900))
        if warning:
            warnings.append(warning)
        current = now or datetime.now(timezone.utc)
        seen_seconds = _unix_seconds(client.get("last_seen_at"))
        age = max(0, int(current.timestamp() - seen_seconds)) if seen_seconds else None
        max_age = int(registry.data.get("max_client_age_seconds", 900))
        online = age <= max_age if age is not None else None
        if online is False:
            warnings.append(f"Client last_seen is older than {max_age} seconds")
        elif online is None:
            warnings.append("Client last_seen is unavailable")
        return {
            "status": "dry_run",
            "rule": {"event_definition_id": rule_id,
                     "title": rule.get("title") or event.get("message"),
                     "event_id": event.get("id")},
            "context": context or {},
            "playbook": {"id": playbook_id, "mode": "manual",
                         "timeout_seconds": playbook.get("timeout_seconds", 300),
                         "row_limit": playbook.get("row_limit", 10000)},
            "target_candidates": candidates,
            "client": {
                "client_id": client.get("client_id"),
                "hostname": (client.get("os_info") or {}).get("hostname"),
                "fqdn": (client.get("os_info") or {}).get("fqdn"),
                "system": (client.get("os_info") or {}).get("system"),
                "last_seen_age_seconds": age,
                "online_within_configured_threshold": online,
            },
            "match_evidence": matches,
            "time_window": window,
            "artifacts": artifacts,
            "evidence_files": ["graylog/context.json", "resolver.json",
                               "velociraptor/collection.json", "velociraptor/errors.json",
                               "manifest.json"],
            "warnings": warnings,
            "execution": _execution_block(),
        }
    except PlaybookError as error:
        return _error(error.code, error.message, error.details)
