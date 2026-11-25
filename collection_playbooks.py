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
_BUILDERS = {
    "empty", "linux_pslist", "linux_netstat", "linux_last_logins",
    "linux_authorized_keys", "linux_bash_history", "darwin_netstat",
    "darwin_packages", "darwin_authorized_keys", "windows_pslist",
    "windows_netstat", "windows_startup", "windows_services", "windows_tasks",
    "windows_explicit_logon", "windows_rdp_auth", "windows_security_evtx",
    "windows_log_modifications", "windows_cleared_logs", "windows_ps_scriptblock",
    "windows_ps_module", "windows_recent_docs", "windows_prefetch",
    "windows_task_events",
}
_REASON_CODES = {
    "rule_disabled", "non_alert_informational", "ambiguous_endpoint_target",
    "external_analysis_target", "health_or_availability",
    "network_or_external_monitor", "application_control_plane",
    "report_or_system_notification",
}
_PLATFORMS = {"linux", "darwin", "windows"}
_ARTIFACT_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.]+$")
_MAX_PATTERN = 128
_MAX_TIMEOUT = 600
_MAX_ROWS = 10000


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
        installed = set(data.get("installed_artifacts") or [])
        for playbook_id, playbook in self.playbooks.items():
            if playbook.get("platform") not in _PLATFORMS or playbook.get("mode") != "manual":
                raise PlaybookError("invalid_registry", "Invalid platform or mode",
                                    {"playbook": playbook_id})
            try:
                timeout = int(playbook.get("timeout_seconds", 300))
                row_limit = int(playbook.get("row_limit", _MAX_ROWS))
                window = int(playbook.get("time_window_seconds", 900))
            except (TypeError, ValueError) as error:
                raise PlaybookError("invalid_registry", "Invalid playbook limits",
                                    {"playbook": playbook_id}) from error
            if not 1 <= timeout <= _MAX_TIMEOUT or not 1 <= row_limit <= _MAX_ROWS \
                    or not 1 <= window <= 86400:
                raise PlaybookError("invalid_registry", "Playbook limits exceed boundary",
                                    {"playbook": playbook_id})
            artifacts = playbook.get("artifacts") or []
            if not artifacts:
                raise PlaybookError("invalid_registry", f"Empty artifacts: {playbook_id}")
            names = set()
            for artifact in artifacts:
                name = artifact.get("name")
                if not isinstance(name, str) or not _ARTIFACT_NAME.fullmatch(name) \
                        or name in names or (installed and name not in installed):
                    raise PlaybookError("invalid_registry", "Invalid or duplicate artifact",
                                        {"playbook": playbook_id, "artifact": name})
                names.add(name)
                if set(artifact) != {"name", "parameter_builder"}:
                    raise PlaybookError("invalid_registry", "Unexpected artifact fields",
                                        {"playbook": playbook_id, "artifact": name})
                if artifact.get("parameter_builder") not in _BUILDERS:
                    raise PlaybookError(
                        "invalid_registry", "Unapproved artifact parameter builder",
                        {"playbook": playbook_id, "artifact": name})
        for rule_id, rule in self.rules.items():
            decision = rule.get("decision", "collect")
            if not rule_id:
                raise PlaybookError("invalid_registry", "Empty rule id")
            if decision == "collect":
                if rule.get("playbook") not in self.playbooks:
                    raise PlaybookError("invalid_registry", "Unknown playbook in rule mapping",
                                        {"rule_id": rule_id})
            elif decision in {"no_collection", "needs_review"}:
                if rule.get("reason_code") not in _REASON_CODES or rule.get("playbook"):
                    raise PlaybookError("invalid_registry", "Invalid non-collection decision",
                                        {"rule_id": rule_id})
            else:
                raise PlaybookError("invalid_registry", "Unknown rule decision",
                                    {"rule_id": rule_id})
        coverage = data.get("coverage") or {}
        if coverage:
            enabled = sum(
                rule.get("state") == "ENABLED" and rule.get("alert") is True
                for rule in self.rules.values())
            if coverage.get("total_rules") != len(self.rules) \
                    or coverage.get("enabled_alert_rules") != enabled:
                raise PlaybookError("invalid_registry", "Coverage totals do not match rules")

    @classmethod
    def load(cls, path=DEFAULT_REGISTRY):
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def select(self, rule_id):
        rule = self.rules.get(str(rule_id or ""))
        if not rule:
            raise PlaybookError("needs_review", "No approved playbook for event_definition_id",
                                {"event_definition_id": str(rule_id or ""),
                                 "reason_code": "unknown_rule"})
        decision = rule.get("decision", "collect")
        if decision in {"no_collection", "needs_review"}:
            raise PlaybookError(
                decision, "Rule does not authorize endpoint collection",
                {"event_definition_id": str(rule_id), "reason_code": rule["reason_code"]})
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


def _name_fingerprint(value):
    """Ignore case and host-name separators; ambiguity still fails closed."""
    return re.sub(r"[^a-z0-9]", "", normalize_name(value))


def _client_aliases(client):
    os_info = client.get("os_info") or {}
    aliases = set()
    for field in ("hostname", "fqdn"):
        value = normalize_name(os_info.get(field))
        if value:
            aliases.add(value)
            aliases.add(_short_name(value))
    aliases.update(filter(None, (_name_fingerprint(value) for value in set(aliases))))
    return aliases


def resolve_client(candidates, clients, expected_platform=None):
    """Resolve one client by normalized hostname/FQDN/short name, never by IOC."""
    matches = {}
    evidence = []
    for hint in candidates:
        value = normalize_name(hint.get("value"))
        fingerprint = _name_fingerprint(value)
        for client in clients:
            aliases = _client_aliases(client)
            if value and (value in aliases or (fingerprint and fingerprint in aliases)):
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
            value = re.split(r"[/\\]", value)[-1]
        if len(value) > limit:
            return ".", f"Ignored overlong filter field: {name}"
        return re.escape(value), None
    return ".", None


def _regex_values(fields, names, kind, limit=5):
    values, invalid = [], []
    for name in names:
        value = fields.get(name)
        if not isinstance(value, (str, int)) or isinstance(value, bool) \
                or not str(value).strip():
            continue
        value = str(value).strip()
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


def _network_parameters(builder, fields):
    warnings = []
    process, warning = _literal_pattern(fields, ("process", "comm", "exe", "image"), basename=True)
    if warning:
        warnings.append(warning)
    ips, bad_ips = _regex_values(
        fields, ("src_ip", "dst_ip", "dest_ip", "srcip", "dstip"), "ip")
    ports, bad_ports = _regex_values(fields, ("dst_port", "dest_port", "port"), "port")
    username, warning = _literal_pattern(fields, ("user", "username"), limit=64)
    if warning:
        warnings.append(warning)
    warnings.extend("Ignored invalid IP filter: " + name for name in bad_ips)
    warnings.extend("Ignored invalid port filter: " + name for name in bad_ports)
    parameters = {
        "IPRegex": "|".join(re.escape(value) for value in ips) or ".",
        "PortRegex": "|".join(ports) or ".",
        "ProcessNameRegex": process,
        "UsernameRegex": username,
        "ConnectionStatusRegex": "LISTEN|ESTAB",
        "ProcessPathRegex": ".",
        "CommandLineRegex": ".",
        "CallChainRegex": ".",
    }
    if builder == "darwin_netstat":
        parameters["AlsoCollectFullProcessTree"] = False
    elif builder == "windows_netstat":
        parameters.pop("ConnectionStatusRegex")
        parameters.pop("CallChainRegex")
        parameters.update({
            "Family": "ALL", "Type": "ALL", "Status": "ALL",
            "HashRegex": ".", "AuthenticodeSubjectRegex": ".",
            "AuthenticodeIssuerRegex": ".", "AuthenticodeVerified": "ALL",
            "DumpProcess": False, "KillProcess": False,
            "DISABLE_DANGEROUS_API_CALLS": True,
        })
    return parameters, warnings


def _bounded_window(window, after="DateAfter", before="DateBefore"):
    if not window:
        raise PlaybookError(
            "invalid_event_timestamp",
            "A valid event timestamp is required for time-bounded artifact collection")
    return {after: window["start"], before: window["end"]}


def _event_id_regex(fields):
    values = []
    for name in ("event_id", "eventid", "winlogbeat_event_id",
                 "winlogbeat_winlog_event_id"):
        value = fields.get(name)
        for item in str(value or "").split(","):
            item = item.strip()
            if item.isdigit() and 0 < int(item) <= 65535 and item not in values:
                values.append(item)
    return "|".join(values) or "."


def build_parameters(builder, fields, window=None):
    """Build typed artifact parameters without accepting VQL or arbitrary keys."""
    if builder == "empty":
        return {}, []
    if builder in {"linux_netstat", "darwin_netstat", "windows_netstat"}:
        return _network_parameters(builder, fields)

    warnings = []
    process, warning = _literal_pattern(
        fields, ("process", "comm", "exe", "image"), basename=True)
    if warning:
        warnings.append(warning)
    username, warning = _literal_pattern(fields, ("user", "username"), limit=64)
    if warning:
        warnings.append(warning)

    if builder == "linux_pslist":
        return {"processRegex": process}, warnings
    if builder == "linux_last_logins":
        return {
            "wtmpGlobs": "/var/log/wtmp*", "MaxCount": 1000,
            "LoginType": "Interactive Sessions", "recent_x_days": 2,
            "excluded_users": "ansible|LOGIN",
        }, warnings
    if builder == "linux_authorized_keys":
        return {"sshKeyFilesGlob": "/home/*/.ssh/authorized_keys*", "AlsoUpload": False}, warnings
    if builder == "linux_bash_history":
        return {"TargetGlob": "/{root,home/*}/.*_history", "SearchRegex": process}, warnings
    if builder == "darwin_packages":
        return {"Length": 10000}, warnings
    if builder == "darwin_authorized_keys":
        parameters = {
            "SearchFilesGlob": "/Users/*/.ssh/authorized_keys*",
            "SearchFilesGlobTable": "Glob\n/Users/*/.ssh/authorized_keys*\n",
            "Fetch_Xattr": True, "Upload_File": False, "Calculate_Hash": True,
            "DoNotFollowSymlinks": True, "UPLOAD_IS_RESUMABLE": False,
        }
        parameters.update(_bounded_window(window, "MoreRecentThan", "ModifiedBefore"))
        return parameters, warnings
    if builder == "windows_pslist":
        return {
            "ProcessRegex": process, "PidRegex": ".", "ExePathRegex": ".",
            "CommandLineRegex": ".", "UsernameRegex": username,
            "DISABLE_DANGEROUS_API_CALLS": True,
        }, warnings
    if builder == "windows_startup":
        return {"AlsoUpload": False}, warnings
    if builder == "windows_services":
        return {
            "Calculate_hashes": False, "CertificateInfo": False, "NameRegex": ".",
            "DisplayNameRegex": ".", "PathNameRegex": ".", "ServiceDllRegex": ".",
            "FailureCommandRegex": ".", "DISABLE_DANGEROUS_API_CALLS": True,
        }, warnings
    if builder == "windows_tasks":
        return {"AlsoUpload": False, "UploadCommands": False, "Username": ".*"}, warnings
    if builder == "windows_explicit_logon":
        parameters = {
            "EvtxGlob": "%SystemRoot%\\System32\\Winevt\\Logs\\Security.evtx",
            "UsernameRegex": username, "UsernameWhitelist": "\\\\$$",
            "ServerRegex": ".", "ServerWhitelist": "localhost",
            "ProcessNameRegex": ".", "VSSAnalysisAge": 0,
        }
        parameters.update(_bounded_window(window))
        return parameters, warnings
    if builder == "windows_rdp_auth":
        ips, bad_ips = _regex_values(fields, ("src_ip", "source_ip"), "ip")
        warnings.extend("Ignored invalid IP filter: " + name for name in bad_ips)
        parameters = {
            "Security": "%SystemRoot%\\System32\\Winevt\\Logs\\Security.evtx",
            "System": "%SystemRoot%\\System32\\Winevt\\Logs\\System.evtx",
            "LocalSessionManager": "%SystemRoot%\\System32\\Winevt\\Logs\\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
            "RemoteConnectionManager": "%SystemRoot%\\System32\\Winevt\\Logs\\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
            "SourceIPRegex": "|".join(re.escape(value) for value in ips) or ".+",
            "UserNameRegex": username if username != "." else ".+",
            "UserNameWhitelist": "\\$$", "VSSAnalysisAge": 0,
        }
        parameters.update(_bounded_window(window))
        return parameters, warnings
    if builder == "windows_security_evtx":
        parameters = {
            "EvtxGlob": "%SystemRoot%\\System32\\winevt\\Logs\\Security.evtx",
            "VSSAnalysisAge": 0, "PathRegex": ".", "ChannelRegex": "Security",
            "IDRegex": _event_id_regex(fields),
        }
        parameters.update(_bounded_window(window, "StartDate", "EndDate"))
        return parameters, warnings
    if builder == "windows_log_modifications":
        parameters = {"ProviderRegex": "."}
        parameters.update(_bounded_window(window))
        return parameters, warnings
    if builder == "windows_cleared_logs":
        parameters = {
            "TargetGlob": "C:\\Windows\\System32\\Winevt\\Logs\\{System,Security}.evtx",
            "VSSAnalysisAge": 0,
        }
        parameters.update(_bounded_window(window))
        return parameters, warnings
    if builder == "windows_ps_scriptblock":
        parameters = {
            "EvtxGlob": "%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
            "SearchStrings": process, "LogLevel": "All", "VSSAnalysisAge": 0,
        }
        parameters.update(_bounded_window(window))
        return parameters, warnings
    if builder == "windows_ps_module":
        parameters = {
            "EventLog": "C:\\Windows\\system32\\winevt\\logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
            "ContextRegex": ".", "PayloadRegex": process, "VSSAnalysisAge": 0,
        }
        parameters.update(_bounded_window(window))
        return parameters, warnings
    if builder == "windows_recent_docs":
        parameters = {"EntryRegex": ".", "UserRegex": username, "SidRegex": "."}
        parameters.update(_bounded_window(window))
        return parameters, warnings
    if builder == "windows_prefetch":
        parameters = {
            "prefetchGlobs": "C:\\Windows\\Prefetch\\*.pf", "binaryRegex": process,
            "IncludeFilesAccessed": False,
        }
        parameters.update(_bounded_window(window, "dateAfter", "dateBefore"))
        return parameters, warnings
    if builder == "windows_task_events":
        parameters = {
            "Security": "%SystemRoot%\\System32\\Winevt\\Logs\\Security.evtx",
            "TaskScheduler": "%SystemRoot%\\System32\\Winevt\\Logs\\Microsoft-Windows-TaskScheduler%4Operational.evtx",
            "TaskSchedulerEventRegex": ".", "SecurityEventRegex": "^(4698|4699|4700|4701|4702)$",
            "TaskNameRegex": ".", "TaskActionRegex": ".", "UserNameRegex": username,
            "IocRegex": ".", "VSSAnalysisAge": 0,
        }
        parameters.update(_bounded_window(window))
        return parameters, warnings
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
        window, warning = _event_window(event, playbook.get("time_window_seconds", 900))
        warnings = [warning] if warning else []
        artifacts = []
        schemas = registry.data.get("artifact_schemas") or {}
        for artifact in playbook["artifacts"]:
            parameters, parameter_warnings = build_parameters(
                artifact["parameter_builder"], event.get("fields") or {}, window)
            unknown_parameters = sorted(set(parameters) - set(schemas.get(artifact["name"], parameters)))
            if unknown_parameters:
                raise PlaybookError(
                    "invalid_registry", "Artifact parameters exceed the installed schema",
                    {"artifact": artifact["name"], "parameters": unknown_parameters})
            warnings.extend(parameter_warnings)
            artifacts.append({"name": artifact["name"], "parameters": parameters,
                              "upload": False})
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
                         "row_limit": playbook.get("row_limit", _MAX_ROWS)},
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
