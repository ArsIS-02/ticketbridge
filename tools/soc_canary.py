#!/usr/bin/env python3
"""Scheduled end-to-end SOC canary: GELF -> Graylog -> TicketBridge -> IRIS.

The default setup mode is read-only. A successful run closes only the alert
containing its own unique ID, with IRIS status Closed and resolution Legitimate.
Failures are reported independently through Zabbix trapper metrics; authenticated
GELF is a fallback when the trapper path is unavailable.
"""
from __future__ import annotations

import argparse
import base64
import gzip
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

TITLE = "HEALTH - SOC canary: сквозная проверка"
NOTIFICATION_TITLE = "GLPI Ticket (TicketBridge)"
DEFAULT_STATE = "/home/redos/zabbix-suite/canary-state.json"
DEFAULT_HISTORY = "/home/redos/zabbix-suite/canary-history"
CA = os.environ.get("ZABBIX_CA", "/home/redos/caddy-internal-root.crt")
CTX = ssl.create_default_context(cafile=CA if Path(CA).exists() else None)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def private_dump(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)


def load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return {}


def template(value: str) -> dict:
    return {"data_type": "string", "providers": [{
        "type": "template-v1", "template": value,
        "require_values": False, "exclude_empty_fields": True,
    }]}


def canary_definition(notification_id: str) -> dict:
    return {
        "title": TITLE,
        "description": (
            "Ежедневная контрольная проверка цепочки GELF → Graylog → TicketBridge → IRIS. "
            "События создаются только инструментом soc_canary.py. Успешный тест автоматически "
            "закрывает собственный алерт как Legitimate; GLPI-заявка для Low не создаётся."
        ),
        "priority": 1,
        "alert": True,
        "config": {
            "type": "aggregation-v1",
            "query": "soc_canary:true",
            "query_parameters": [], "filters": [],
            "streams": [], "stream_categories": [],
            "group_by": ["soc_canary_id"],
            "series": [{"type": "count", "id": "count-", "field": None}],
            "conditions": {"expression": {
                "expr": ">=", "left": {"expr": "number-ref", "ref": "count-"},
                "right": {"expr": "number", "value": 1.0},
            }},
            # Non-overlapping windows prevent one GELF message from firing twice.
            "search_within_ms": 60000, "execute_every_ms": 60000,
            "use_cron_scheduling": False, "cron_expression": None,
            "cron_timezone": None, "event_limit": 10,
        },
        "field_spec": {
            "event": template("${source.message}"),
            "host": template("${source.source}"),
            "soc_canary_id": template("${source.soc_canary_id}"),
        },
        "key_spec": ["soc_canary_id"],
        "notification_settings": {"grace_period_ms": 0, "backlog_size": 1},
        "notifications": [{"notification_id": notification_id, "notification_parameters": None}],
        "storage": [{"type": "persist-to-streams-v1",
                     "streams": ["000000000000000000000002"]}],
        "tags": ["health", "canary", "low"],
        "state": "ENABLED",
    }


class Graylog:
    def __init__(self, url: str, token: str):
        self.base = url.rstrip("/")
        auth = base64.b64encode((token + ":token").encode()).decode()
        self.headers = {"Accept": "application/json", "X-Requested-By": "soc-canary",
                        "Authorization": "Basic " + auth}

    def request(self, method: str, path: str, body=None):
        data = None if body is None else json.dumps(body, ensure_ascii=False).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers=self.headers)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")[:500]
            raise RuntimeError(f"Graylog {method} {path}: HTTP {error.code}: {detail}") from error
        return json.loads(raw) if raw.strip() else {}

    def definitions(self) -> list[dict]:
        result, page = [], 1
        while True:
            body = self.request("GET", f"/api/events/definitions?per_page=100&page={page}")
            chunk = body.get("event_definitions", body.get("elements", []))
            result.extend(chunk)
            total = body.get("total", body.get("grand_total", len(result)))
            if not chunk or len(result) >= total:
                return result
            page += 1

    def find_definition(self) -> dict:
        found = [row for row in self.definitions() if row.get("title") == TITLE]
        if len(found) != 1:
            raise RuntimeError(f"Expected exactly one canary definition, found {len(found)}")
        return found[0]

    def source_message(self, canary_id: str, started: datetime):
        params = {"query": f'soc_canary_id:"{canary_id}"',
                  "from": iso(started - timedelta(seconds=5)),
                  "to": iso(utcnow() + timedelta(minutes=1)), "limit": 20,
                  "fields": "source,message,soc_canary,soc_canary_id"}
        body = self.request("GET", "/api/search/universal/absolute?" + urllib.parse.urlencode(params))
        for wrapper in body.get("messages", []):
            message = wrapper.get("message", wrapper)
            if str(message.get("soc_canary_id")) == canary_id:
                return message
        return None

    def event(self, definition_id: str, canary_id: str, started: datetime):
        body = self.request("POST", "/api/events/search", {
            "query": "", "page": 1, "per_page": 100,
            "timerange": {"type": "absolute", "from": iso(started - timedelta(seconds=5)),
                          "to": iso(utcnow() + timedelta(minutes=1))},
            "filter": {"alerts": "include", "event_definitions": [definition_id]},
            "sort_by": "timestamp", "sort_direction": "desc",
        })
        for wrapper in body.get("events", []):
            event = wrapper.get("event", wrapper)
            fields = event.get("fields") or {}
            if str(fields.get("soc_canary_id")) == canary_id or canary_id in str(fields.get("event", "")):
                return event
        return None


class Iris:
    def __init__(self, url: str, key: str):
        self.base = url.rstrip("/")
        self.key = key

    def request(self, method: str, path: str, body=None):
        data = None if body is None else json.dumps(body, ensure_ascii=False).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Accept": "application/json",
                                              "Authorization": "Bearer " + self.key})
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30, context=CTX) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")[:500]
            raise RuntimeError(f"IRIS {method} {path}: HTTP {error.code}: {detail}") from error
        return json.loads(raw) if raw.strip() else {}

    def find_alert(self, canary_id: str):
        for page in range(1, 6):
            body = self.request("GET", "/api/v2/alerts?" + urllib.parse.urlencode({
                "per_page": 100, "page": page, "sort": "desc", "order_by": "alert_id"}))
            data = body.get("data", body)
            if isinstance(data, dict):
                data = data.get("alerts", data.get("data", []))
            if not isinstance(data, list):
                raise RuntimeError("Unexpected IRIS alert list format")
            matches = [alert for alert in data if alert_has_id(alert, canary_id)]
            if len(matches) > 1:
                raise RuntimeError(f"Several IRIS alerts contain canary ID {canary_id}")
            if matches:
                return matches[0]
            if len(data) < 100:
                break
        return None

    def close_own_alert(self, alert: dict, canary_id: str, comment: str) -> int:
        if not alert_has_id(alert, canary_id):
            raise RuntimeError("Refusing to close an alert without the exact canary ID")
        alert_id = int(alert["alert_id"])
        self.request("PUT", f"/api/v2/alerts/{alert_id}",
                     {"alert_status_id": 6, "alert_resolution_status_id": 6})
        self.request("POST", f"/api/v2/alerts/{alert_id}/comments",
                     {"comment_text": comment})
        return alert_id

    def verified_closed(self, alert_id: int):
        alert = self.request("GET", f"/api/v2/alerts/{alert_id}")
        if (int(alert.get("alert_status_id") or 0) == 6
                and int(alert.get("alert_resolution_status_id") or 0) == 6):
            return alert
        return None


def alert_has_id(alert: dict, canary_id: str) -> bool:
    """Match only alert-owned text, never a list position or another alert's ID."""
    return any(canary_id in str(alert.get(field) or "")
               for field in ("alert_title", "alert_description", "alert_source_ref"))


def gelf_payload(canary_id: str, timestamp: float | None = None) -> dict:
    return {
        "version": "1.1", "host": "soc-canary",
        "short_message": f"SOC canary {canary_id}: контрольная сквозная проверка",
        "timestamp": timestamp if timestamp is not None else time.time(), "level": 6,
        "_soc_canary": "true", "_soc_canary_id": canary_id,
        "_source_tool": "soc-canary",
    }


def send_gelf_udp(host: str, port: int, payload: dict) -> None:
    # GELF UDP accepts gzip natively. Unlike GELF TCP, UDP must not be NUL-terminated.
    encoded = gzip.compress(json.dumps(payload, ensure_ascii=False).encode())
    if len(encoded) > 8192:
        raise ValueError("Canary GELF datagram is unexpectedly large")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(10)
        sock.sendto(encoded, (host, port))


def wait_for(stage: str, function, timeout: int, interval: float = 5.0,
             monotonic=time.monotonic, sleep=time.sleep):
    deadline = monotonic() + timeout
    last_error = None
    while True:
        try:
            value = function()
            if value:
                return value
        except Exception as error:  # transient API failures are retried until the stage deadline
            last_error = str(error)[:300]
        if monotonic() >= deadline:
            suffix = f"; last error: {last_error}" if last_error else ""
            raise TimeoutError(f"Stage {stage} timed out after {timeout}s{suffix}")
        sleep(interval)


def setup(graylog: Graylog, apply: bool, backup_dir: Path) -> dict:
    definitions = graylog.definitions()
    found = [row for row in definitions if row.get("title") == TITLE]
    if len(found) > 1:
        raise RuntimeError(f"Duplicate canary definitions: {[row.get('id') for row in found]}")
    notifications = graylog.request("GET", "/api/events/notifications?per_page=200&page=1").get("notifications", [])
    matching = [row for row in notifications if row.get("title") == NOTIFICATION_TITLE]
    if len(matching) != 1:
        raise RuntimeError(f"Expected one TicketBridge notification, found {len(matching)}")
    notification = graylog.request("GET", f"/api/events/notifications/{matching[0]['id']}")
    desired = canary_definition(notification["id"])
    result = {"action": "update" if found else "create", "applied": apply,
              "title": TITLE, "priority": 1, "query": desired["config"]["query"],
              "notification": NOTIFICATION_TITLE}
    if not apply:
        result["existing_id"] = found[0]["id"] if found else None
        result["note"] = "Dry-run only; no Graylog objects changed"
        return result

    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    backup = backup_dir / f"soc-canary-{stamp}"
    backup.mkdir(parents=True, mode=0o700, exist_ok=False)
    private_dump(backup / "before.json", {"definitions": definitions, "notification": notification})
    if found:
        definition_id = found[0]["id"]
        # Graylog 7 wraps only create in entity; update requires the matching ID directly.
        graylog.request("GET", f"/api/events/definitions/{definition_id}")
        graylog.request("PUT", f"/api/events/definitions/{definition_id}",
                        dict(desired, id=definition_id))
    else:
        created = graylog.request("POST", "/api/events/definitions", {"entity": desired})
        definition_id = created.get("id") or (created.get("event_definition") or {}).get("id")
    if not definition_id:
        raise RuntimeError("Graylog did not return the canary definition ID")
    persisted = graylog.request("GET", f"/api/events/definitions/{definition_id}")
    expected = canary_definition(notification["id"])
    for key in ("title", "priority", "alert", "config", "field_spec", "key_spec",
                "notification_settings", "notifications", "storage", "tags", "state"):
        if persisted.get(key) != expected[key]:
            raise RuntimeError(f"Canary verification failed for {key}: {persisted.get(key)!r}")
    private_dump(backup / "after.json", persisted)
    result.update({"id": definition_id, "state": persisted["state"],
                   "backup": str(backup), "verified": True})
    return result


def report_metrics(state_path: Path, history_dir: Path, state: dict, healthy: bool,
                   started_monotonic: float) -> dict:
    previous = load_state(state_path)
    if previous.get("fallback_event_id") and not state.get("fallback_event_id"):
        state["fallback_event_id"] = previous["fallback_event_id"]
    state["finished_at"] = utcnow().isoformat()
    state["status"] = "ok" if healthy else "failed"
    state["latency_seconds"] = round(time.monotonic() - started_monotonic, 3)
    private_dump(state_path, state)
    private_dump(history_dir / f"{state['canary_id']}.json", state)
    metrics = {"soc.canary.heartbeat": int(time.time()),
               "soc.canary.status": int(healthy),
               "soc.canary.latency": state["latency_seconds"]}
    try:
        from soc_watchdog import send_trapper
        send_trapper(metrics)
        state["monitoring"] = "zabbix-accepted"
    except Exception as error:
        state["monitoring"] = "zabbix-error: " + str(error)[:200]
        try:
            from soc_watchdog import send_gelf
            event_id = previous.get("fallback_event_id") or f"soc-canary-{utcnow():%Y%m%d}"
            detail = state.get("error") or "Canary succeeded, but Zabbix trapper is unavailable"
            send_gelf(event_id, "PROBLEM", detail)
            state["fallback_event_id"] = event_id
            state["monitoring"] += "; gelf-fallback-sent"
        except Exception as fallback_error:
            state["monitoring"] += "; gelf-fallback-error: " + str(fallback_error)[:200]
    else:
        # Resolve a previous fallback only after both the canary and trapper recover.
        event_id = previous.get("fallback_event_id")
        if healthy and event_id:
            try:
                from soc_watchdog import send_gelf
                send_gelf(event_id, "RESOLVED", "SOC canary and Zabbix trapper recovered")
                state["fallback_event_id"] = None
                state["monitoring"] += "; previous-fallback-resolved"
            except Exception as error:
                state["monitoring"] += "; fallback-recovery-error: " + str(error)[:200]
    private_dump(state_path, state)
    private_dump(history_dir / f"{state['canary_id']}.json", state)
    return metrics


def run(args) -> dict:
    token = os.environ.get("TB_GRAYLOG_TOKEN") or os.environ.get("GRAYLOG_TOKEN", "")
    iris_url = os.environ.get("TB_IRIS_URL") or os.environ.get("IRIS_URL", "")
    iris_key = os.environ.get("TB_IRIS_KEY") or os.environ.get("IRIS_KEY", "")
    if not all((token, iris_url, iris_key)):
        raise SystemExit("Set TB_GRAYLOG_TOKEN, TB_IRIS_URL and TB_IRIS_KEY")
    graylog = Graylog(os.environ.get("GRAYLOG_API", "http://127.0.0.1:9000"), token)
    iris = Iris(iris_url, iris_key)
    definition = graylog.find_definition()
    canary_id = "soc-canary-" + uuid.uuid4().hex
    started = utcnow()
    started_monotonic = time.monotonic()
    state_path = Path(args.state)
    history_dir = Path(args.history)
    previous = load_state(state_path)
    state = {"canary_id": canary_id, "definition_id": definition["id"],
             "started_at": started.isoformat(), "status": "running", "stages": {},
             "notification": "IRIS alert_created is expected; mailbox delivery is not asserted"}
    if previous.get("fallback_event_id"):
        state["fallback_event_id"] = previous["fallback_event_id"]
    private_dump(state_path, state)
    healthy = False
    current_stage = "gelf"
    try:
        send_gelf_udp(os.environ.get("TB_GELF_HOST", "127.0.0.1"),
                      int(os.environ.get("TB_GELF_PORT", "12206")), gelf_payload(canary_id))
        state["stages"]["gelf"] = {"sent_at": utcnow().isoformat()}
        private_dump(state_path, state)

        for stage, timeout, function in (
            ("graylog_message", args.message_timeout,
             lambda: graylog.source_message(canary_id, started)),
            ("graylog_event", args.event_timeout,
             lambda: graylog.event(definition["id"], canary_id, started)),
            ("iris_alert", args.iris_timeout, lambda: iris.find_alert(canary_id)),
        ):
            current_stage = stage
            stage_started = time.monotonic()
            value = wait_for(stage, function, timeout, args.interval)
            state["stages"][stage] = {"latency_seconds": round(time.monotonic() - stage_started, 3)}
            if stage == "graylog_message":
                state["graylog_message_id"] = value.get("_id") or value.get("id")
            elif stage == "graylog_event":
                state["graylog_event_id"] = value.get("id")
            else:
                state["iris_alert_id"] = int(value["alert_id"])
                state["alert_title"] = value.get("alert_title")
            private_dump(state_path, state)

        current_stage = "iris_closed"
        comment = (f"SOC canary {canary_id}: цепочка Graylog → TicketBridge → IRIS проверена. "
                   "Автозакрытие контрольного события; реальной угрозы нет. Вердикт: Legitimate.")
        iris.close_own_alert(value, canary_id, comment)
        verified = wait_for("iris_closed", lambda: iris.verified_closed(state["iris_alert_id"]),
                            args.close_timeout, args.interval)
        state["stages"]["iris_closed"] = {
            "status": verified["alert_status_id"],
            "resolution_status": verified["alert_resolution_status_id"],
        }
        healthy = True
        return state
    except Exception as error:
        state["error"] = str(error)[:500]
        state["failed_stage"] = current_stage
        return state
    finally:
        metrics = report_metrics(state_path, history_dir, state, healthy, started_monotonic)
        state["metrics"] = metrics
        print(json.dumps(state, ensure_ascii=False, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    setup_parser = sub.add_parser("setup", help="dry-run or create/update the dedicated Graylog rule")
    setup_parser.add_argument("--apply", action="store_true")
    setup_parser.add_argument("--backup-dir", default="/home/redos/ticketbridge/backups")
    run_parser = sub.add_parser("run", help="execute one isolated end-to-end canary")
    run_parser.add_argument("--state", default=DEFAULT_STATE)
    run_parser.add_argument("--history", default=DEFAULT_HISTORY)
    run_parser.add_argument("--message-timeout", type=int, default=90)
    run_parser.add_argument("--event-timeout", type=int, default=180)
    run_parser.add_argument("--iris-timeout", type=int, default=180)
    run_parser.add_argument("--close-timeout", type=int, default=60)
    run_parser.add_argument("--interval", type=float, default=5.0)
    args = parser.parse_args()
    if args.command == "setup":
        token = os.environ.get("TB_GRAYLOG_TOKEN") or os.environ.get("GRAYLOG_TOKEN", "")
        if not token:
            raise SystemExit("Set TB_GRAYLOG_TOKEN or GRAYLOG_TOKEN")
        result = setup(Graylog(os.environ.get("GRAYLOG_API", "http://127.0.0.1:9000"), token),
                       args.apply, Path(args.backup_dir))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    result = run(args)
    if result["status"] != "ok" or not str(result.get("monitoring", "")).startswith("zabbix-accepted"):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
