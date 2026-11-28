#!/usr/bin/env python3
"""Independent Zabbix/Graylog/IRIS/TicketBridge watchdog with GELF fallback."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import time
from urllib import request

CA = os.environ.get("ZABBIX_CA", "/home/redos/caddy-internal-root.crt")
CTX = ssl.create_default_context(cafile=CA if Path(CA).exists() else None)
STATE = Path(os.environ.get("WATCHDOG_STATE", "/home/redos/zabbix-suite/watchdog-state.json"))
HOMEWIKI = "https://homewiki.apps.monitoring.test/rules/art-zabbix-graylog-iris"
ZABBIX_WEB = "https://zabbix.apps.monitoring.test/zabbix/"


def api_json(url, method="GET", payload=None, headers=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = request.Request(url, data=data, method=method,
                          headers={"Content-Type": "application/json", **(headers or {})})
    with request.urlopen(req, timeout=12, context=CTX) as response:
        raw = response.read()
        return response.status, json.loads(raw) if raw.strip() else {}


def check_zabbix():
    status, body = api_json(os.environ["ZABBIX_API"], "POST", {
        "jsonrpc": "2.0", "method": "apiinfo.version", "params": {}, "id": 1})
    return status == 200 and bool(body.get("result")), f"HTTP {status}, version={body.get('result')}"


def check_graylog():
    token = os.environ.get("GRAYLOG_TOKEN", "")
    auth = base64.b64encode(f"{token}:token".encode()).decode()
    status, _ = api_json(os.environ["GRAYLOG_API"].rstrip("/") + "/api/system",
                         headers={"Authorization": "Basic " + auth})
    return status == 200, f"HTTP {status}"


def check_iris():
    status, _ = api_json(os.environ["IRIS_URL"].rstrip("/") + "/api/v2/alerts?per_page=1",
                         headers={"Authorization": "Bearer " + os.environ["IRIS_KEY"]})
    return status == 200, f"HTTP {status}"


def check_ticketbridge():
    status, body = api_json(os.environ["TICKETBRIDGE_URL"])
    return status == 200 and body.get("ok") is True, f"HTTP {status}, ok={body.get('ok')}"


def send_trapper(metrics):
    clock = int(time.time())
    host = os.environ.get("WATCHDOG_HOST", "homeserver.monitoring.test")
    payload = json.dumps({"request": "sender data", "clock": clock, "data": [
        {"host": host, "key": key, "value": str(value), "clock": clock}
        for key, value in metrics.items()]}).encode()
    packet = b"ZBXD\x01" + struct.pack("<Q", len(payload)) + payload
    with socket.create_connection((os.environ.get("ZABBIX_SENDER_HOST", "homeserver.monitoring.test"),
                                   int(os.environ.get("ZABBIX_SENDER_PORT", "10051"))), timeout=12) as sock:
        sock.sendall(packet)
        header = b""
        while len(header) < 13:
            chunk = sock.recv(13 - len(header))
            if not chunk:
                raise RuntimeError("Truncated Zabbix sender response")
            header += chunk
        if header[:5] != b"ZBXD\x01":
            raise RuntimeError("Invalid Zabbix sender response")
        length = struct.unpack("<Q", header[5:])[0]
        body = b""
        while len(body) < length:
            chunk = sock.recv(length - len(body))
            if not chunk:
                raise RuntimeError("Truncated Zabbix sender body")
            body += chunk
    result = json.loads(body)
    if result.get("response") != "success" or "failed: 0" not in result.get("info", ""):
        raise RuntimeError(f"Zabbix sender rejected metrics: {result}")
    return result


def send_gelf_payload(payload):
    req = request.Request(os.environ["GRAYLOG_GELF_URL"], method="POST",
                          data=json.dumps(payload, ensure_ascii=False).encode(),
                          headers={"Content-Type": "application/json",
                                   "Authorization": os.environ["GRAYLOG_GELF_AUTH"]})
    with request.urlopen(req, timeout=12, context=CTX) as response:
        response.read()
        if not 200 <= response.status < 300:
            raise RuntimeError(f"GELF fallback HTTP {response.status}")


def send_gelf(event_id, status, detail):
    send_gelf_payload({
        "version": "1.1", "host": "soc-watchdog",
        "short_message": f"SOC watchdog: Zabbix {status}: {detail}",
        "timestamp": time.time(), "level": 2 if status == "PROBLEM" else 6,
        "_zabbix_event_id": event_id,
        "_zabbix_event_status": status,
        "_zabbix_event_value": 1 if status == "PROBLEM" else 0,
        "_zabbix_severity": "High" if status == "PROBLEM" else "Information",
        "_zabbix_nseverity": 4 if status == "PROBLEM" else 0,
        "_zabbix_trigger_id": "soc-watchdog-zabbix",
        "_zabbix_trigger_description": "Independent watchdog: Zabbix is unavailable",
        "_zabbix_event_duration": "00:00:00",
        "_zabbix_tags_json": json.dumps({"runbook": HOMEWIKI, "scope": "selfmonitor"}),
        "_zabbix_url": ZABBIX_WEB + "zabbix.php?action=problem.view",
        "_source_tool": "soc-watchdog",
    })


def collect_inotify_usage():
    """Count inotify watches visible to the watchdog user and identify the largest consumer."""
    usage = {}
    commands = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        fd_dir = f"/proc/{entry}/fd"
        try:
            fds = os.listdir(fd_dir)
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        for fd in fds:
            try:
                if os.readlink(f"{fd_dir}/{fd}") != "anon_inode:inotify":
                    continue
                with open(f"/proc/{entry}/fdinfo/{fd}", encoding="utf-8") as source:
                    usage[entry] = usage.get(entry, 0) + sum(
                        line.startswith("inotify") for line in source)
            except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
                continue
        if usage.get(entry):
            try:
                with open(f"/proc/{entry}/cmdline", "rb") as source:
                    commands[entry] = source.read().replace(b"\0", b" ").decode(
                        errors="replace").strip()
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                commands[entry] = ""
    limit = int(Path("/proc/sys/fs/inotify/max_user_watches").read_text().strip())
    top_pid, top_watches = max(usage.items(), key=lambda item: item[1], default=("", 0))
    total = sum(usage.values())
    return {
        "total": total, "limit": limit, "percent": round(100 * total / limit, 2),
        "top_pid": top_pid, "top_watches": top_watches,
        "top_command": commands.get(top_pid, "")[:160],
    }


def send_inotify_gelf(event_id, status, severity, usage):
    problem = status == "PROBLEM"
    runbook = "https://homewiki.apps.monitoring.test/rules/art-monitoring-restore"
    detail = (f"{usage['total']}/{usage['limit']} watches ({usage['percent']}%); "
              f"top: pid={usage['top_pid'] or '-'} watches={usage['top_watches']} "
              f"cmd={usage['top_command'] or '-'}")
    send_gelf_payload({
        "version": "1.1", "host": socket.gethostname(),
        "short_message": f"SOC watchdog: inotify {severity}: {detail}",
        "timestamp": time.time(),
        "level": (2 if severity == "CRITICAL" else 4) if problem else 6,
        "_zabbix_event_id": event_id,
        "_zabbix_event_status": status,
        "_zabbix_event_value": int(problem),
        "_zabbix_severity": ({"CRITICAL": "High", "WARNING": "Average"}.get(severity, "Information")),
        "_zabbix_nseverity": {"CRITICAL": 4, "WARNING": 3}.get(severity, 0),
        "_zabbix_trigger_id": "soc-watchdog-inotify",
        "_zabbix_trigger_description": f"inotify watches {severity}: {detail}",
        "_zabbix_event_duration": "00:00:00",
        "_zabbix_tags_json": json.dumps({"runbook": runbook, "scope": "selfmonitor"}),
        "_zabbix_url": runbook,
        "_source_tool": "soc-watchdog",
        "_inotify_watches": usage["total"],
        "_inotify_limit": usage["limit"],
        "_inotify_percent": usage["percent"],
        "_inotify_top_pid": str(usage["top_pid"]),
        "_inotify_top_watches": usage["top_watches"],
        "_inotify_top_command": usage["top_command"],
    })


def check_inotify(state, deliver=True):
    """Send only threshold transitions; retain active state if delivery fails."""
    usage = collect_inotify_usage()
    warn = float(os.environ.get("INOTIFY_WARN_PERCENT", "70"))
    critical = float(os.environ.get("INOTIFY_CRIT_PERCENT", "85"))
    recover = float(os.environ.get("INOTIFY_RECOVER_PERCENT", "60"))
    if not 0 <= recover < warn < critical <= 100:
        raise ValueError("Require 0 <= INOTIFY_RECOVER_PERCENT < INOTIFY_WARN_PERCENT < INOTIFY_CRIT_PERCENT <= 100")
    previous = state.get("inotify", {})
    old_status = previous.get("status", "OK")
    if usage["percent"] >= critical:
        status = "CRITICAL"
    elif usage["percent"] >= warn:
        status = "WARNING"
    elif old_status in {"WARNING", "CRITICAL"} and usage["percent"] > recover:
        status = old_status
    else:
        status = "OK"
    result = {**usage, "status": status, "delivery": "not-needed"}
    active = old_status in {"WARNING", "CRITICAL"}
    changed = status != old_status and (status != "OK" or active)
    if changed:
        event_id = previous.get("event_id") or f"inotify-{socket.gethostname()}"
        if not deliver:
            result["delivery"] = "graylog-unavailable"
            return result
        try:
            send_inotify_gelf(event_id, "RESOLVED" if status == "OK" else "PROBLEM", status, usage)
            state["inotify"] = {"status": status, "event_id": event_id,
                                "updated": datetime.now(timezone.utc).isoformat()}
            result["delivery"] = "sent"
        except Exception as error:
            result["delivery"] = "error: " + str(error)[:200]
    elif status == "OK" and old_status != "OK":
        state["inotify"] = {"status": "OK", "updated": datetime.now(timezone.utc).isoformat()}
    return result


def load_state():
    try:
        return json.loads(STATE.read_text())
    except (FileNotFoundError, ValueError):
        return {}


def save_state(state):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n")
    STATE.chmod(0o600)


def main():
    checks = {}
    details = {}
    for name, function in (("zabbix", check_zabbix), ("graylog", check_graylog),
                           ("iris", check_iris), ("ticketbridge", check_ticketbridge)):
        try:
            checks[name], details[name] = function()
        except Exception as error:
            checks[name], details[name] = False, str(error)[:250]
    metrics = {"soc.watchdog.heartbeat": int(time.time())}
    metrics.update({f"soc.watchdog[{name}]": int(healthy) for name, healthy in checks.items()})
    try:
        send_trapper(metrics)
        sender = "ok"
    except Exception as error:
        checks["zabbix"] = False
        details["zabbix"] = str(error)[:250]
        sender = "error"

    # If Zabbix itself cannot carry an alarm, bypass it through the existing
    # authenticated GELF input. The same event ID is used for later recovery.
    state = load_state()
    active = state.get("zabbix_event_id")
    if not checks["zabbix"] and checks["graylog"]:
        if not active:
            active = f"watchdog-zabbix-{int(time.time())}"
            state["zabbix_event_id"] = active
        try:
            send_gelf(active, "PROBLEM", details["zabbix"])
            state["fallback"] = "problem-sent"
        except Exception as error:
            state["fallback"] = "error: " + str(error)[:200]
    elif checks["zabbix"] and active and checks["graylog"]:
        try:
            send_gelf(active, "RESOLVED", "Zabbix API and trapper recovered")
            state.pop("zabbix_event_id", None)
            state["fallback"] = "resolved-sent"
        except Exception as error:
            state["fallback"] = "recovery-error: " + str(error)[:200]
    try:
        inotify = check_inotify(state, deliver=checks["graylog"])
    except Exception as error:
        inotify = {"status": "ERROR", "delivery": str(error)[:250]}
    state["last_run"] = datetime.now(timezone.utc).isoformat()
    save_state(state)
    print(json.dumps({"status": "ok", "checks": checks, "details": details,
                      "sender": sender, "fallback": state.get("fallback", "not-needed"),
                      "inotify": inotify}, ensure_ascii=False))
    # A machine-readable non-zero status allows systemd to record watchdog failure,
    # while the next timer invocation still runs normally.
    if not all(checks.values()) or inotify["status"] == "ERROR":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
