#!/usr/bin/env python3
"""Минимальная отладка комментариев IRIS: создать алерт, POST+GET комментарий, удалить."""
import json
import sys
from urllib import request, error

sys.path.insert(0, "/home/redos/ticketbridge")
import app  # noqa: E402  (даёт app.IRIS, app.IRIS_KEY, app.CTX)


def api(method, path, payload=None):
    req = request.Request(app.IRIS + path, method=method,
                          data=None if payload is None else json.dumps(payload).encode())
    req.add_header("Authorization", "Bearer " + app.IRIS_KEY)
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with request.urlopen(req, timeout=20, context=app.CTX) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw.strip() else {})
    except error.HTTPError as e:
        return e.code, e.read().decode()[:500]


alert_id = None
try:
    st, body = api("POST", app.IRIS_API_PATH, {
        "alert_title": "DEBUG comment api — удалить",
        "alert_severity_id": 4,
        "alert_status_id": 2,
        "alert_customer_id": 1,
        "alert_source": "ticketbridge-debug",
        "alert_description": "Временный алерт для отладки комментариев API.",
    })
    print("CREATE alert:", st, json.dumps(body, ensure_ascii=False)[:300])
    alert_id = (body.get("data") or {}).get("alert_id") or body.get("alert_id")
    print("alert_id =", alert_id)
    if not alert_id:
        sys.exit(1)

    st, body = api("POST", f"/api/v2/alerts/{alert_id}/comments",
                   {"comment_text": "debug comment 12345"})
    print("POST comment:", st, json.dumps(body, ensure_ascii=False)[:400])

    st, body = api("GET", f"/api/v2/alerts/{alert_id}/comments")
    print("GET comments:", st, json.dumps(body, ensure_ascii=False)[:600])
finally:
    if alert_id:
        st, body = api("DELETE", f"/api/v2/alerts/{alert_id}")
        print("DELETE alert:", st)
