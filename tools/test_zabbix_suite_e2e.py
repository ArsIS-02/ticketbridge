#!/usr/bin/env python3
"""Two-phase real Zabbix -> Graylog -> IRIS severity/recovery test with cleanup."""
import json
import os
from pathlib import Path
import sys
import time
from urllib import parse, request

sys.path.insert(0, "/home/redos/ticketbridge")
sys.path.insert(0, "/home/redos/zabbix-suite")
import app
from soc_watchdog import send_trapper
from zabbix_suite import Zabbix

TRIGGER_ID = "25560"
HOST = "homeserver.monitoring.test"
ITEM_KEY = "graylog.integration.test"
STATE = Path("/home/redos/zabbix-suite/e2e-state.json")
z = Zabbix("Admin", os.environ["ZABBIX_PASSWORD"])


def iris_api(method, path, payload=None):
    req = request.Request(app.IRIS + path, method=method,
                          data=None if payload is None else json.dumps(payload).encode())
    req.add_header("Authorization", "Bearer " + app.IRIS_KEY)
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    with request.urlopen(req, timeout=20, context=app.CTX) as response:
        raw = response.read()
        return json.loads(raw) if raw.strip() else {}


def alert_list(event_id):
    result = []
    for page in range(1, 101):
        body = iris_api("GET", "/api/v2/alerts?" + parse.urlencode({"per_page": 100, "page": page}))
        data = body.get("data", body)
        if isinstance(data, dict):
            data = data.get("alerts", data.get("data", []))
        result.extend(a for a in data if str(a.get("alert_source_ref")) == f"zabbix:{event_id}")
        if len(data) < 100:
            break
    return result


def wait_for(function, timeout=250):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = function()
        if last:
            return last
        time.sleep(5)
    raise TimeoutError(f"Condition not reached; last={last}")


def latest_problem(start):
    events = z.call("event.get", {"output": ["eventid", "clock", "value"],
                                  "triggerids": [TRIGGER_ID], "source": 0, "object": 0,
                                  "value": 1, "time_from": start - 2,
                                  "sortfield": ["eventid"], "sortorder": "DESC", "limit": 1})
    return events[0] if events else None


def cleanup(event_id):
    if event_id:
        for alert in alert_list(event_id):
            iris_api("DELETE", f"/api/v2/alerts/{alert['alert_id']}")
            print(json.dumps({"cleanup": "iris_alert_deleted", "id": alert["alert_id"]}), flush=True)
        con = app.state_db()
        con.execute("DELETE FROM iris_dedup WHERE dedup_key=?", (f"zabbix:{event_id}",))
        con.commit()
        con.close()


phase = sys.argv[1]
if phase == "problem":
    started = int(time.time())
    original = z.call("trigger.get", {"output": ["triggerid", "priority"], "triggerids": [TRIGGER_ID]})[0]
    STATE.write_text(json.dumps({"started": started, "original_priority": original["priority"]}))
    STATE.chmod(0o600)
    event_id = None
    try:
        z.call("trigger.update", {"triggerid": TRIGGER_ID, "priority": 4})
        # API немедленно возвращает новый priority, но рабочий конфигурационный
        # кэш Zabbix обновляется асинхронно. Без ожидания webhook может получить
        # прежнюю важность Warning, хотя trigger.get уже показывает High.
        time.sleep(65)
        send_trapper({ITEM_KEY: 1})
        event = wait_for(lambda: latest_problem(started))
        event_id = event["eventid"]
        alerts = wait_for(lambda: alert_list(event_id) or None)
        assert len(alerts) == 1, alerts
        alert_id = alerts[0]["alert_id"]
        detail = iris_api("GET", f"/api/v2/alerts/{alert_id}")
        assert int(detail["alert_severity_id"]) == 5, detail.get("alert_severity_id")
        assert detail["alert_title"].startswith("[Zabbix] Graylog integration test"), detail["alert_title"]
        description = detail.get("alert_description") or ""
        for label in ("🚨 Событие Zabbix", "🔎 Replay Search в Graylog", "📖 Рунбук в HomeWiki"):
            assert label in description, label
        STATE.write_text(json.dumps({"started": started, "original_priority": original["priority"],
                                     "event_id": event_id, "alert_id": alert_id}))
        STATE.chmod(0o600)
        print(json.dumps({"phase": "problem", "result": "passed", "event_id": event_id,
                          "alert_id": alert_id, "iris_severity": detail["alert_severity_id"],
                          "title": detail["alert_title"], "links_verified": 3}), flush=True)
    except Exception:
        cleanup(event_id)
        STATE.unlink(missing_ok=True)
        raise
    finally:
        z.call("trigger.update", {"triggerid": TRIGGER_ID, "priority": int(original["priority"])})
        print(json.dumps({"cleanup": "trigger_priority_restored",
                          "priority": original["priority"]}), flush=True)

elif phase == "recover":
    state = json.loads(STATE.read_text())
    event_id, alert_id = state["event_id"], state["alert_id"]
    try:
        send_trapper({ITEM_KEY: 0})
        closed = wait_for(lambda: (lambda current: current if int(current.get("alert_status_id", 0)) == 6 else None)(
            iris_api("GET", f"/api/v2/alerts/{alert_id}")))
        # Комментарий восстановления отправляется следом за закрытием статуса,
        # поэтому опрашиваем, пока он не появится, а не читаем один раз.
        def recovery_comments():
            body = iris_api("GET", f"/api/v2/alerts/{alert_id}/comments")
            text = json.dumps(body, ensure_ascii=False)
            return body if event_id in text else None

        comments = wait_for(recovery_comments, timeout=60)
        serialized = json.dumps(comments, ensure_ascii=False)
        assert "Рунбук в HomeWiki" in serialized, serialized[:500]
        print(json.dumps({"phase": "recover", "result": "passed", "event_id": event_id,
                          "alert_id": alert_id, "status": closed["alert_status_id"],
                          "recovery_comment_verified": True}), flush=True)
    finally:
        cleanup(event_id)
        STATE.unlink(missing_ok=True)
        print(json.dumps({"cleanup": "dedup_and_state_removed", "event_id": event_id}), flush=True)
else:
    raise SystemExit("Usage: test_zabbix_suite_e2e.py problem|recover")
