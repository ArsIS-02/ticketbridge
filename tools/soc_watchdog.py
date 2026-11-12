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


def send_gelf(event_id, status, detail):
    payload = {
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
    }
    req = request.Request(os.environ["GRAYLOG_GELF_URL"], method="POST",
                          data=json.dumps(payload, ensure_ascii=False).encode(),
                          headers={"Content-Type": "application/json",
                                   "Authorization": os.environ["GRAYLOG_GELF_AUTH"]})
    with request.urlopen(req, timeout=12, context=CTX) as response:
        response.read()
        if not 200 <= response.status < 300:
            raise RuntimeError(f"GELF fallback HTTP {response.status}")


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
    state["last_run"] = datetime.now(timezone.utc).isoformat()
    save_state(state)
    print(json.dumps({"status": "ok", "checks": checks, "details": details,
                      "sender": sender, "fallback": state.get("fallback", "not-needed")},
                     ensure_ascii=False))
    # A machine-readable non-zero status allows systemd to record watchdog failure,
    # while the next timer invocation still runs normally.
    if not all(checks.values()):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
