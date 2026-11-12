#!/usr/bin/env python3
"""Idempotent Zabbix 6.4 service, map, self-monitoring and analytics suite."""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import ssl
import statistics
import time
from urllib import request

ZABBIX_API = os.environ.get(
    "ZABBIX_API", "https://zabbix.apps.monitoring.test/zabbix/api_jsonrpc.php")
CA = os.environ.get("ZABBIX_CA", "/home/redos/caddy-internal-root.crt")
SSL_CONTEXT = ssl.create_default_context(cafile=CA)
HOMEWIKI = "https://homewiki.apps.monitoring.test/rules/art-zabbix-graylog-iris"
GRAYLOG = "https://graylog.apps.monitoring.test"
ZABBIX_WEB = "https://zabbix.apps.monitoring.test/zabbix/"
PREFIX = "HL / "
MAP_NAME = "HomeLab — SOC and infrastructure"
WATCHDOG_HOST = "homeserver.monitoring.test"
SENSITIVE_KEYS = {"password", "passwd", "secret", "token", "auth", "api_key",
                  "graylog_auth", "session_token"}

APP_GROUPS = {
    "SOC": {"Attack Map", "BlockBoard", "DFIR-IRIS", "GLPI", "Graylog",
            "GraylogBackup", "GraylogRuleTester", "HomeRepo", "HomeWiki",
            "LogAtlas", "sigma2graylog", "TrafficLens", "Velociraptor", "VolWeb",
            "Wazuh", "ZaSlon"},
    "Monitoring": {"Alertmanager", "Beszel", "cAdvisor", "Dozzle", "Grafana",
                   "Komodo", "NetAlertX", "Node Exporter", "Observium", "Portainer",
                   "Prometheus", "WatchYourLAN", "Zabbix", "Zabbix GELF endpoint"},
    "Applications": {"Atrium", "FreeIPA", "HostDeck", "Jenkins", "Webmin"},
    "Infrastructure": {"Caddy"},
}


class Zabbix:
    def __init__(self, username: str, password: str):
        self.request_id = 0
        self.auth = None
        self.version = self.call("apiinfo.version", {}, authenticated=False)
        self.auth = self.call("user.login", {
            "username": username, "password": password}, authenticated=False)

    def call(self, method: str, params, authenticated: bool = True):
        self.request_id += 1
        body = {"jsonrpc": "2.0", "method": method, "params": params,
                "id": self.request_id}
        if authenticated and self.auth:
            body["auth"] = self.auth
        req = request.Request(ZABBIX_API, data=json.dumps(body).encode(), method="POST")
        req.add_header("Content-Type", "application/json-rpc")
        with request.urlopen(req, timeout=90, context=SSL_CONTEXT) as response:
            result = json.load(response)
        if "error" in result:
            raise RuntimeError(f"{method}: {result['error']}")
        return result["result"]


def redact(value, key=""):
    """Recursively remove credentials before exporting audit data."""
    if any(part in key.lower() for part in SENSITIVE_KEYS):
        return "<redacted>"
    if isinstance(value, dict):
        # Media type parameters store the sensitive name and its value in
        # sibling fields: {"name": "graylog_auth", "value": "..."}.
        parameter_name = str(value.get("name", ""))
        if "value" in value and any(part in parameter_name.lower()
                                    for part in SENSITIVE_KEYS):
            return {k: ("<redacted>" if k == "value" else redact(v, k))
                    for k, v in value.items()}
        return {k: redact(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, key) for v in value]
    return value


def private_dump(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    path.chmod(0o600)


def audit(z: Zabbix) -> dict:
    queries = {
        "hostgroups": ("hostgroup.get", {"output": ["groupid", "name"]}),
        "hosts": ("host.get", {
            "output": ["hostid", "host", "name", "status", "description"],
            "selectGroups": ["groupid", "name"],
            "selectInterfaces": "extend", "limit": 1000}),
        "triggers": ("trigger.get", {
            "output": ["triggerid", "description", "expression", "priority", "status",
                       "value", "comments", "url"],
            "selectTags": "extend", "selectHosts": ["hostid", "host", "name"],
            "selectDependencies": ["triggerid", "description"], "limit": 5000}),
        "actions": ("action.get", {
            "output": "extend", "selectOperations": "extend",
            "selectRecoveryOperations": "extend", "selectUpdateOperations": "extend"}),
        "mediatypes": ("mediatype.get", {"output": "extend"}),
        "services": ("service.get", {
            "output": "extend", "selectParents": "extend", "selectChildren": "extend",
            "selectTags": "extend", "selectProblemTags": "extend",
            "selectStatusRules": "extend"}),
        "slas": ("sla.get", {
            "output": "extend", "selectServiceTags": "extend",
            "selectSchedule": "extend", "selectExcludedDowntimes": "extend"}),
        "maps": ("map.get", {
            "output": "extend", "selectSelements": "extend", "selectLinks": "extend",
            "selectUrls": "extend"}),
        "maintenances": ("maintenance.get", {
            "output": "extend", "selectGroups": "extend", "selectHosts": "extend",
            "selectTimeperiods": "extend", "selectTags": "extend"}),
        "dashboards": ("dashboard.get", {"output": ["dashboardid", "name", "userid", "private"]}),
    }
    data = {"metadata": {"created_at": datetime.now(timezone.utc).isoformat(),
                         "zabbix_version": z.version, "api": ZABBIX_API}}
    for key, (method, params) in queries.items():
        data[key] = z.call(method, params)
    return redact(data)


def get_services(z: Zabbix):
    return z.call("service.get", {
        "output": "extend", "selectParents": "extend", "selectChildren": "extend",
        "selectTags": "extend", "selectProblemTags": "extend", "selectStatusRules": "extend"})


def ensure_service(z: Zabbix, existing: dict, name: str, tags: list,
                   problem_tags: list | None = None, children: list | None = None,
                   sortorder: int = 0):
    data = {"name": name, "algorithm": 2, "sortorder": sortorder, "weight": 0,
            "description": "HomeLab service tree; managed by zabbix_suite.py",
            "tags": tags}
    if problem_tags is not None:
        data["problem_tags"] = problem_tags
    if children is not None:
        data["children"] = [{"serviceid": str(service_id)} for service_id in children]
    if name in existing:
        service_id = existing[name]["serviceid"]
        z.call("service.update", dict(data, serviceid=service_id))
        return int(service_id), "updated"
    service_id = z.call("service.create", data)["serviceids"][0]
    return int(service_id), "created"


def configure_services(z: Zabbix, output_dir: Path):
    triggers = z.call("trigger.get", {
        "output": ["triggerid", "description", "priority", "status", "url", "flags", "templateid"],
        "selectTags": "extend", "selectHosts": ["hostid", "host", "name"],
        "selectDiscoveryRule": ["itemid"], "limit": 5000})
    services_before = get_services(z)
    maps_before = z.call("map.get", {"output": "extend", "selectSelements": "extend",
                                     "selectLinks": "extend", "selectUrls": "extend"})
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    private_dump(output_dir / f"services-backup-{stamp}.json",
                 {"triggers": triggers, "services": services_before, "maps": maps_before})

    # Only concrete host triggers participate in infrastructure services. Template
    # triggers and the controlled integration test are deliberately excluded.
    changed_tags = 0
    updated_targets = set()
    prototype_cache = {}
    for trigger in triggers:
        tags = trigger.get("tags") or []
        tag_map = {tag["tag"]: tag.get("value", "") for tag in tags}
        hosts = trigger.get("hosts") or []
        is_https = any(host["host"] == "Lab-HTTPS-Applications" for host in hosts)
        concrete_host = len(hosts) == 1 and hosts[0]["host"] not in {
            "Lab-HTTPS-Applications", "Linux by Zabbix agent", "Windows by Zabbix agent"}
        selected_host = (tag_map.get("integration") == "graylog" and concrete_host
                         and tag_map.get("scope") in {"availability", "capacity"})
        if tag_map.get("integration") != "graylog":
            continue
        desired = list(tags)
        if is_https or selected_host:
            if "runbook" not in tag_map:
                desired.append({"tag": "runbook", "value": HOMEWIKI})
            if selected_host and "service_host" not in tag_map:
                # Discovered triggers are read-only. Update their host-level
                # prototype and let LLD propagate the macro to concrete triggers.
                host_value = ("{HOST.HOST}" if int(trigger.get("flags") or 0) == 4
                              else hosts[0]["host"])
                desired.append({"tag": "service_host", "value": host_value})
        target_id = trigger["triggerid"]
        if int(trigger.get("flags") or 0) == 4:
            discovery_id = (trigger.get("discoveryRule") or {}).get("itemid")
            if discovery_id not in prototype_cache:
                prototype_cache[discovery_id] = z.call("triggerprototype.get", {
                    "output": ["triggerid", "description"], "discoveryids": [discovery_id]})
            candidates = []
            for prototype in prototype_cache[discovery_id]:
                parts = re.split(r"\{#[^}]+\}", prototype["description"])
                pattern = ".*?".join(re.escape(part) for part in parts)
                if re.fullmatch(pattern, trigger["description"]):
                    candidates.append(prototype)
            if len(candidates) != 1:
                raise RuntimeError(f"Cannot identify prototype for discovered trigger "
                                   f"{trigger['triggerid']} {trigger['description']!r}")
            target_id = candidates[0]["triggerid"]
        if desired != tags and target_id not in updated_targets:
            method = ("triggerprototype.update" if int(trigger.get("flags") or 0) == 4
                      else "trigger.update")
            try:
                z.call(method, {"triggerid": target_id, "tags": desired})
            except RuntimeError as error:
                raise RuntimeError(f"Tag update failed for trigger={trigger['triggerid']} "
                                   f"target={target_id} flags={trigger.get('flags')} "
                                   f"description={trigger['description']!r}: {error}") from error
            updated_targets.add(target_id)
            changed_tags += 1

    applications = sorted({tag["value"] for trigger in triggers for tag in trigger.get("tags", [])
                           if tag.get("tag") == "application" and tag.get("value")})
    assigned = set().union(*APP_GROUPS.values())
    if set(applications) != assigned:
        raise RuntimeError(f"Application group mapping mismatch: unassigned={set(applications)-assigned}, "
                           f"missing={assigned-set(applications)}")
    existing = {service["name"]: service for service in services_before}
    counters = defaultdict(int)
    app_ids = {}
    for group_name in ("SOC", "Monitoring", "Applications", "Infrastructure"):
        for index, app in enumerate(sorted(APP_GROUPS[group_name])):
            name = f"{PREFIX}App / {app}"
            service_id, action = ensure_service(
                z, existing, name,
                [{"tag": "sla_group", "value": group_name.lower()},
                 {"tag": "service_type", "value": "application"}],
                [{"tag": "application", "operator": 0, "value": app}], sortorder=index)
            app_ids[app] = service_id
            counters[f"{action}_services"] += 1

    # Re-read so newly added service_host tags are authoritative. Prototypes
    # and unresolved host macros are not concrete infrastructure services.
    triggers_after = z.call("trigger.get", {
        "output": ["triggerid", "flags"], "selectTags": "extend",
        "selectHosts": ["hostid", "host"], "limit": 5000})
    host_names = sorted({trigger["hosts"][0]["host"] for trigger in triggers_after
                         if len(trigger.get("hosts") or []) == 1
                         and int(trigger.get("flags") or 0) != 1
                         and trigger["hosts"][0]["host"] not in {
                             "Lab-HTTPS-Applications", "Linux by Zabbix agent", "Windows by Zabbix agent"}
                         and any(tag.get("tag") == "service_host" and tag.get("value")
                                 and not tag.get("value", "").startswith("{")
                                 for tag in trigger.get("tags", []))})
    host_ids = {}
    for index, host in enumerate(host_names):
        service_id, action = ensure_service(
            z, existing, f"{PREFIX}Host / {host}",
            [{"tag": "sla_group", "value": "infrastructure"},
             {"tag": "service_type", "value": "host"}],
            [{"tag": "service_host", "operator": 0, "value": host}], sortorder=index)
        host_ids[host] = service_id
        counters[f"{action}_services"] += 1

    group_ids = {}
    for index, group_name in enumerate(("SOC", "Monitoring", "Applications", "Infrastructure")):
        children = [app_ids[app] for app in sorted(APP_GROUPS[group_name])]
        if group_name == "Infrastructure":
            children += list(host_ids.values())
        service_id, action = ensure_service(
            z, existing, f"{PREFIX}{group_name}",
            [{"tag": "service_group", "value": group_name.lower()}],
            children=children, sortorder=index)
        group_ids[group_name] = service_id
        counters[f"{action}_services"] += 1
    root_id, action = ensure_service(
        z, existing, f"{PREFIX}HomeLab", [{"tag": "service_root", "value": "homelab"}],
        children=list(group_ids.values()))
    counters[f"{action}_services"] += 1

    # Initial SLO targets are explicit assumptions, not measured commitments.
    slas_before = {sla["name"]: sla for sla in z.call("sla.get", {"output": "extend"})}
    effective_date = int(datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    for group_name in ("SOC", "Monitoring", "Applications", "Infrastructure"):
        name = f"HomeLab / {group_name} / 99.5%"
        data = {"name": name, "slo": "99.5", "period": 1,
                "timezone": "Asia/Yekaterinburg",
                "description": "Initial 24x7 SLO target; review after collecting representative history.",
                "effective_date": effective_date, "status": 1, "schedule": [],
                "service_tags": [{"tag": "sla_group", "operator": 0,
                                  "value": group_name.lower()}],
                "excluded_downtimes": []}
        if name in slas_before:
            z.call("sla.update", dict(data, slaid=slas_before[name]["slaid"]))
            counters["updated_slas"] += 1
        else:
            z.call("sla.create", data)
            counters["created_slas"] += 1

    counters["updated_trigger_tags"] = changed_tags
    counters["applications"] = len(app_ids)
    counters["infrastructure_hosts"] = len(host_ids)
    counters["root_service_id"] = root_id
    return dict(counters)


def configure_map(z: Zabbix):
    hosts = z.call("host.get", {"output": ["hostid", "host", "name", "status"],
                                "filter": {"status": 0}, "limit": 1000})
    hosts = sorted(hosts, key=lambda host: host["host"])
    positions = {
        "homelab.monitoring.test": (550, 60),
        "homeserver.monitoring.test": (300, 300),
        "redos-server.monitoring.test": (600, 300),
        "Lab-HTTPS-Applications": (900, 300),
        "wazuh.monitoring.test": (900, 560),
        "wazuh-homelab.monitoring.test": (600, 560),
        "server.monitoring.test": (300, 560),
        "redos-raspi.monitoring.test": (80, 300),
        "RedOSRP16.monitoring.test": (900, 60),
        "DC.arsentyev.local": (80, 60),
        "W11-Desktop": (300, 60),
        "RedOS-Workstation": (80, 560),
    }
    ids = {host["host"]: str(index + 1) for index, host in enumerate(hosts)}
    elements = []
    for host in hosts:
        x, y = positions.get(host["host"], (100, 700))
        elements.append({
            "selementid": ids[host["host"]], "elementtype": 0,
            "elements": [{"hostid": host["hostid"]}], "iconid_off": "2",
            "use_iconmap": 0, "label": host["name"], "x": x, "y": y,
            "urls": [
                {"name": "Zabbix problems", "url": ZABBIX_WEB +
                 "zabbix.php?action=problem.view&filter_hostids[]={HOST.ID}"},
                {"name": "Graylog search", "url": GRAYLOG +
                 "/search?q=host%3A{HOST.NAME}&rangetype=relative&relative=86400"},
                {"name": "SOC runbook", "url": HOMEWIKI},
            ],
        })
    pairs = [
        ("homeserver.monitoring.test", "redos-server.monitoring.test"),
        ("redos-server.monitoring.test", "Lab-HTTPS-Applications"),
        ("redos-server.monitoring.test", "wazuh.monitoring.test"),
        ("redos-server.monitoring.test", "wazuh-homelab.monitoring.test"),
        ("redos-server.monitoring.test", "server.monitoring.test"),
        ("redos-server.monitoring.test", "redos-raspi.monitoring.test"),
        ("redos-server.monitoring.test", "RedOSRP16.monitoring.test"),
        ("homelab.monitoring.test", "homeserver.monitoring.test"),
        ("homelab.monitoring.test", "DC.arsentyev.local"),
        ("homelab.monitoring.test", "W11-Desktop"),
        ("homelab.monitoring.test", "RedOS-Workstation"),
    ]
    links = [{"selementid1": ids[a], "selementid2": ids[b], "label": "monitoring"}
             for a, b in pairs if a in ids and b in ids]
    data = {"name": MAP_NAME, "width": 1100, "height": 760, "grid_show": 1,
            "grid_size": 50, "highlight": 1, "expandproblem": 1,
            "selements": elements, "links": links, "urls": [
                {"name": "HomeWiki SOC guide", "url": HOMEWIKI},
                {"name": "Graylog", "url": GRAYLOG + "/alerts"},
            ]}
    existing = z.call("map.get", {"output": ["sysmapid", "name"], "filter": {"name": MAP_NAME}})
    if existing:
        map_id = existing[0]["sysmapid"]
        z.call("map.update", dict(data, sysmapid=map_id))
        action = "updated"
    else:
        map_id = z.call("map.create", data)["sysmapids"][0]
        action = "created"
    verify = z.call("map.get", {"output": ["sysmapid", "name"], "sysmapids": [map_id],
                                "selectSelements": "extend", "selectLinks": "extend"})
    assert len(verify[0].get("selements", [])) == len(elements)
    assert len(verify[0].get("links", [])) == len(links)
    return {"action": action, "map_id": map_id, "name": MAP_NAME,
            "elements": len(elements), "links": len(links)}


def upgrade_media_metadata(z: Zabbix):
    """Add the trigger name separately from TRIGGER.DESCRIPTION (comments)."""
    media = z.call("mediatype.get", {"output": "extend", "filter": {"name": "Graylog"}})[0]
    params = {p["name"]: p.get("value", "") for p in media.get("parameters", [])}
    if params.get("event_name") != "{EVENT.NAME}":
        raise RuntimeError("Graylog media type has no EVENT.NAME parameter")
    script = media.get("script") or ""
    if "_zabbix_trigger_name" not in script:
        anchor = '        _zabbix_trigger_description: params.trigger_description,'
        if anchor not in script:
            raise RuntimeError("Cannot locate trigger_description in Graylog media script")
        script = script.replace(
            anchor, '        _zabbix_trigger_name: params.event_name,\n' + anchor, 1)
        z.call("mediatype.update", {"mediatypeid": media["mediatypeid"], "script": script})
    verify = z.call("mediatype.get", {"output": ["mediatypeid", "script"],
                                      "mediatypeids": [media["mediatypeid"]]})[0]
    assert '_zabbix_trigger_name: params.event_name' in verify["script"]
    return {"media_id": media["mediatypeid"], "zabbix_trigger_name": "verified"}


def setup_selfmonitor(z: Zabbix, env_path: Path):
    host = z.call("host.get", {"output": ["hostid"], "filter": {"host": WATCHDOG_HOST}})[0]
    item_ids = {}
    specs = [("soc.watchdog.heartbeat", "SOC watchdog heartbeat", 3)]
    specs += [(f"soc.watchdog[{name}]", f"SOC watchdog: {name} health", 3)
              for name in ("zabbix", "graylog", "iris", "ticketbridge")]
    for key, name, value_type in specs:
        data = {"hostid": host["hostid"], "name": name, "key_": key, "type": 2,
                "value_type": value_type, "history": "7d", "trends": "0",
                "description": "Independent SOC watchdog; managed by zabbix_suite.py"}
        found = z.call("item.get", {"output": ["itemid"], "hostids": [host["hostid"]],
                                    "filter": {"key_": key}})
        if found:
            item_id = found[0]["itemid"]
            update = dict(data, itemid=item_id)
            update.pop("hostid")
            z.call("item.update", update)
        else:
            item_id = z.call("item.create", data)["itemids"][0]
        item_ids[key] = item_id
    trigger_specs = [("SOC watchdog heartbeat is stale",
                      f"now()-last(/{WATCHDOG_HOST}/soc.watchdog.heartbeat)>180", 4, "watchdog")]
    trigger_specs += [(f"SOC watchdog: {name} is unavailable",
                       f"last(/{WATCHDOG_HOST}/soc.watchdog[{name}])=0",
                       4 if name != "ticketbridge" else 3, name)
                      for name in ("zabbix", "graylog", "iris", "ticketbridge")]
    for description, expression, priority, component in trigger_specs:
        tags = [{"tag": "integration", "value": "graylog"},
                {"tag": "scope", "value": "selfmonitor"},
                {"tag": "component", "value": component},
                {"tag": "runbook", "value": HOMEWIKI}]
        data = {"description": description, "expression": expression, "priority": priority,
                "status": 0, "comments": "Independent health signal from soc_watchdog.py.",
                "tags": tags}
        found = z.call("trigger.get", {"output": ["triggerid"], "hostids": [host["hostid"]],
                                       "filter": {"description": description}})
        if found:
            z.call("trigger.update", dict(data, triggerid=found[0]["triggerid"]))
        else:
            z.call("trigger.create", data)

    media = z.call("mediatype.get", {"output": "extend", "filter": {"name": "Graylog"}})[0]
    params = {p["name"]: p.get("value", "") for p in media.get("parameters", [])}
    values = {
        "ZABBIX_API": ZABBIX_API, "ZABBIX_CA": CA,
        "ZABBIX_PASSWORD": os.environ["ZABBIX_PASSWORD"],
        "ZABBIX_SENDER_HOST": "homeserver.monitoring.test", "ZABBIX_SENDER_PORT": "10051",
        "WATCHDOG_HOST": WATCHDOG_HOST,
        "GRAYLOG_API": os.environ.get("GRAYLOG_URL", "https://graylog.apps.monitoring.test"),
        "GRAYLOG_TOKEN": os.environ.get("GRAYLOG_TOKEN", ""),
        "GRAYLOG_GELF_URL": params.get("graylog_url", ""),
        "GRAYLOG_GELF_AUTH": params.get("graylog_auth", ""),
        "IRIS_URL": os.environ.get("TB_IRIS_URL", ""),
        "IRIS_KEY": os.environ.get("TB_IRIS_KEY", ""),
        "TICKETBRIDGE_URL": "http://127.0.0.1:8099/health",
    }
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text("".join(f"{key}={json.dumps(value)}\n" for key, value in values.items()))
    env_path.chmod(0o600)
    return {"items": len(item_ids), "triggers": len(trigger_specs),
            "env": str(env_path), "sender": values["ZABBIX_SENDER_HOST"]}


def create_maintenance(z: Zabbix, host_name: str, minutes: int, name: str | None):
    if not 5 <= minutes <= 10080:
        raise ValueError("Maintenance duration must be between 5 and 10080 minutes")
    hosts = z.call("host.get", {"output": ["hostid", "host"], "filter": {"host": host_name}})
    if len(hosts) != 1:
        raise RuntimeError(f"Expected exactly one host {host_name!r}")
    now = int(time.time())
    data = {"name": name or f"HL / Ad-hoc / {host_name} / {datetime.now():%Y%m%d-%H%M%S}",
            "maintenance_type": 0, "active_since": now - 60,
            "active_till": now + minutes * 60, "description": "On-demand maintenance via zabbix_suite.py",
            "hosts": [{"hostid": hosts[0]["hostid"]}], "groups": [], "tags": [],
            "timeperiods": [{"timeperiod_type": 0, "start_date": now, "period": minutes * 60}]}
    maintenance_id = z.call("maintenance.create", data)["maintenanceids"][0]
    verify = z.call("maintenance.get", {"output": "extend", "maintenanceids": [maintenance_id],
                                        "selectHosts": "extend", "selectTimeperiods": "extend"})
    return {"maintenance_id": maintenance_id, "host": host_name, "minutes": minutes,
            "active_till": verify[0]["active_till"], "name": verify[0]["name"]}


def delete_maintenance(z: Zabbix, maintenance_id: int):
    found = z.call("maintenance.get", {"output": ["maintenanceid", "name", "description"],
                                       "maintenanceids": [maintenance_id]})
    if len(found) != 1 or not found[0]["name"].startswith("HL / Ad-hoc /"):
        raise RuntimeError("Refusing to delete an unknown or non-suite maintenance")
    z.call("maintenance.delete", [str(maintenance_id)])
    return {"deleted": maintenance_id}


def seconds_to_hms(seconds: float):
    seconds = int(round(seconds))
    return f"{seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}"


def report(z: Zabbix, output_dir: Path, days: int):
    now = int(time.time())
    start = now - days * 86400
    triggers = z.call("trigger.get", {
        "output": ["triggerid", "description", "priority", "url"],
        "selectTags": "extend", "selectHosts": ["hostid", "host", "name"], "limit": 5000})
    trigger_map = {trigger["triggerid"]: trigger for trigger in triggers}
    events = z.call("event.get", {
        "output": ["eventid", "objectid", "clock", "value", "r_eventid", "r_clock", "acknowledged"],
        "source": 0, "object": 0, "time_from": start, "time_till": now,
        "selectAcknowledges": "extend", "selectTags": "extend",
        "sortfield": ["clock", "eventid"], "sortorder": "ASC", "limit": 10000})
    # Controlled integration tests are excluded from operational noise and MTTR.
    test_triggers = {trigger["triggerid"] for trigger in triggers
                     if any(tag.get("tag") == "scope" and tag.get("value") == "test"
                            for tag in trigger.get("tags", []))}
    events = [event for event in events if event["objectid"] not in test_triggers]
    by_trigger = defaultdict(list)
    for event in events:
        by_trigger[event["objectid"]].append(event)
    noise, flapping, short, durations, acknowledgements = [], [], [], [], []
    for trigger_id, items in by_trigger.items():
        trigger = trigger_map.get(trigger_id, {})
        problems = [event for event in items if event.get("value") == "1"]
        if not problems:
            continue
        hosts = trigger.get("hosts") or [{}]
        runbook = next((tag.get("value") for tag in trigger.get("tags", [])
                        if tag.get("tag") == "runbook" and tag.get("value")), HOMEWIKI)
        base = {"trigger_id": trigger_id, "trigger": trigger.get("description", trigger_id),
                "host": hosts[0].get("host", "unknown"), "problems": len(problems),
                "state_changes": len(items), "runbook": runbook,
                "zabbix_url": ZABBIX_WEB + f"tr_events.php?triggerid={trigger_id}&eventid={problems[-1]['eventid']}"}
        noise.append(base)
        clocks = sorted(int(event["clock"]) for event in items)
        windows = sum(1 for index, clock in enumerate(clocks)
                      if sum(1 for other in clocks[index:] if other - clock <= 600) > 5)
        if windows:
            flapping.append(dict(base, windows_over_five_changes=windows))
        for problem in problems:
            recovery_clock = int(problem.get("r_clock") or 0)
            if recovery_clock > int(problem["clock"]):
                duration = recovery_clock - int(problem["clock"])
                durations.append(duration)
                if duration < 60:
                    short.append(dict(base, event_id=problem["eventid"], duration_seconds=duration))
            acks = problem.get("acknowledges") or []
            if acks:
                delay = min(int(ack["clock"]) for ack in acks) - int(problem["clock"])
                if delay >= 0:
                    acknowledgements.append(delay)
    noise.sort(key=lambda row: (row["problems"], row["state_changes"]), reverse=True)
    flapping.sort(key=lambda row: row["windows_over_five_changes"], reverse=True)
    short.sort(key=lambda row: row["duration_seconds"])
    result = {
        "metadata": {"generated_at": datetime.now(timezone.utc).isoformat(),
                     "period_days": days, "from": start, "to": now,
                     "events_analyzed": len(events), "event_limit": 10000,
                     "limit_reached": len(events) >= 10000, "test_events_excluded": True,
                     "mtta_note": "Time to first acknowledgement recorded in Zabbix; unacknowledged events excluded.",
                     "mttr_note": "Only resolved problem events with r_clock are included."},
        "summary": {"triggers_with_problems": len(noise),
                    "problem_events": sum(row["problems"] for row in noise),
                    "flapping_triggers": len(flapping), "short_resolved_events": len(short),
                    "resolved_events_for_mttr": len(durations),
                    "acknowledged_events_for_mtta": len(acknowledgements),
                    "mttr_seconds": statistics.mean(durations) if durations else None,
                    "mttr_median_seconds": statistics.median(durations) if durations else None,
                    "mtta_seconds": statistics.mean(acknowledgements) if acknowledgements else None},
        "top_noise": noise[:20], "flapping": flapping[:20], "short_events": short[:50],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = output_dir / f"zabbix-analytics-{stamp}.json"
    private_dump(json_path, result)
    latest_json = output_dir / "latest.json"
    private_dump(latest_json, result)
    lines = ["# Zabbix: шум, флаппинг и время реакции", "",
             f"Сформировано: {result['metadata']['generated_at']}",
             f"Период: последние {days} дней. Событий проанализировано: {len(events)}.",
             "Тестовые события `scope=test` исключены.", "",
             "## Сводка", "",
             f"- Проблемных событий: **{result['summary']['problem_events']}**.",
             f"- Триггеров с проблемами: **{len(noise)}**; с флаппингом: **{len(flapping)}**.",
             f"- Коротких восстановлений (< 60 с): **{len(short)}**.",
             f"- MTTR: **{seconds_to_hms(result['summary']['mttr_seconds']) if durations else 'нет данных'}** "
             f"(по {len(durations)} восстановлениям).",
             f"- MTTA: **{seconds_to_hms(result['summary']['mtta_seconds']) if acknowledgements else 'нет данных'}** "
             f"(по {len(acknowledgements)} подтверждениям).", "",
             "MTTR учитывает только события с зарегистрированным восстановлением; MTTA — только подтверждённые события. Это не оценка времени реакции по всем алертам.", "",
             "## Топ источников шума", "",
             "| Хост | Триггер | Проблемы | Изменения | Рунбук |", "|---|---|---:|---:|---|"]
    for row in noise[:20]:
        lines.append(f"| {row['host']} | [{row['trigger']}]({row['zabbix_url']}) | {row['problems']} | "
                     f"{row['state_changes']} | [открыть]({row['runbook']}) |")
    lines += ["", "## Флаппинг: более пяти изменений за 10 минут", "",
              "| Хост | Триггер | Окна | Проблемы |", "|---|---|---:|---:|"]
    for row in flapping[:20]:
        lines.append(f"| {row['host']} | {row['trigger']} | {row['windows_over_five_changes']} | {row['problems']} |")
    if not flapping:
        lines.append("| — | Не обнаружено | 0 | 0 |")
    lines += ["", "## Короткие события (< 60 с)", "",
              "| Хост | Триггер | Длительность | Событие |", "|---|---|---:|---|"]
    for row in short[:20]:
        lines.append(f"| {row['host']} | {row['trigger']} | {row['duration_seconds']} с | {row['event_id']} |")
    if not short:
        lines.append("| — | Не обнаружено | — | — |")
    md_path = output_dir / "latest.md"
    md_path.write_text("\n".join(lines) + "\n")
    print(json.dumps({"status": "ok", "json": str(json_path), "latest_json": str(latest_json),
                      "latest_markdown": str(md_path), "summary": result["summary"]},
                     ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    audit_parser = sub.add_parser("audit")
    audit_parser.add_argument("--output", default="/home/redos/zabbix-suite-audit.json")
    services = sub.add_parser("configure-services")
    services.add_argument("--output-dir", default="/home/redos/zabbix-suite/backups")
    sub.add_parser("configure-map")
    sub.add_parser("upgrade-media-metadata")
    maintenance = sub.add_parser("maintenance-create")
    maintenance.add_argument("--host", required=True)
    maintenance.add_argument("--minutes", type=int, default=60)
    maintenance.add_argument("--name")
    maintenance_delete = sub.add_parser("maintenance-delete")
    maintenance_delete.add_argument("--id", type=int, required=True)
    selfmonitor = sub.add_parser("setup-selfmonitor")
    selfmonitor.add_argument("--env", default="/home/redos/zabbix-suite/watchdog.env")
    report_parser = sub.add_parser("report")
    report_parser.add_argument("--days", type=int, default=7)
    report_parser.add_argument("--output-dir", default="/home/redos/zabbix-suite/reports")
    args = parser.parse_args()
    z = Zabbix(os.environ.get("ZABBIX_USERNAME", "Admin"), os.environ["ZABBIX_PASSWORD"])
    if args.command == "audit":
        data = audit(z)
        out = Path(args.output)
        private_dump(out, data)
        result = {"status": "ok", "version": z.version, "output": str(out),
                  "counts": {k: len(v) for k, v in data.items() if isinstance(v, list)}}
    elif args.command == "configure-services":
        result = configure_services(z, Path(args.output_dir))
    elif args.command == "configure-map":
        result = configure_map(z)
    elif args.command == "upgrade-media-metadata":
        result = upgrade_media_metadata(z)
    elif args.command == "maintenance-create":
        result = create_maintenance(z, args.host, args.minutes, args.name)
    elif args.command == "maintenance-delete":
        result = delete_maintenance(z, args.id)
    elif args.command == "setup-selfmonitor":
        result = setup_selfmonitor(z, Path(args.env))
    elif args.command == "report":
        if not 1 <= args.days <= 90:
            raise ValueError("Report period must be between 1 and 90 days")
        report(z, Path(args.output_dir), args.days)
        return
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
