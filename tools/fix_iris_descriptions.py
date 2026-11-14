#!/usr/bin/env python3
"""Разовая миграция: перегенерировать описания старых алертов IRIS,
созданных TicketBridge с битой вёрсткой (mojibake-эмодзи, сырой JSON,
слипшиеся ссылки). Источник — alert_source_content (исходное событие
Graylog), шаблон — актуальный compose_ticket из app.py.

Запуск на redos-server:  python3 fix_iris_descriptions.py [--apply]
Без --apply только показывает, сколько карточек будет изменено.
"""
import json
import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app import compose_ticket  # noqa: E402

IRIS = os.environ["TB_IRIS_URL"].rstrip("/")
KEY = os.environ["TB_IRIS_KEY"]
APPLY = "--apply" in sys.argv

import ssl
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def api(path, payload=None, method=None):
    req = urllib.request.Request(IRIS + path, method=method or ("PUT" if payload else "GET"))
    req.add_header("Authorization", "Bearer " + KEY)
    req.add_header("Content-Type", "application/json")
    if payload is not None:
        req.data = json.dumps(payload).encode()
    with urllib.request.urlopen(req, timeout=30, context=CTX) as r:
        return json.loads(r.read() or b"{}")


def needs_fix(desc):
    if not desc:
        return False
    return ("ð" in desc) or ('[{"tag"' in desc) or ("{" "HOST.CONN" in desc)


def main():
    page, fixed, skipped, errors = 1, 0, 0, 0
    while True:
        d = api(f"/api/v2/alerts?per_page=100&page={page}&sort=desc")
        alerts = d.get("data") or []
        if not alerts:
            break
        for a in alerts:
            aid = a.get("alert_id")
            desc = a.get("alert_description") or ""
            if not needs_fix(desc):
                skipped += 1
                continue
            src = a.get("alert_source_content")
            if not isinstance(src, dict) or not src.get("message"):
                print(f"#{aid}: нет raw-события, пропуск")
                skipped += 1
                continue
            try:
                title, new_desc, _ = compose_ticket(src)
            except Exception as e:
                print(f"#{aid}: ошибка compose: {e}")
                errors += 1
                continue
            if APPLY:
                try:
                    api(f"/api/v2/alerts/{aid}",
                        {"alert_title": (a.get("alert_title") or title)[:250],
                         "alert_description": new_desc})
                    fixed += 1
                    print(f"#{aid}: обновлено")
                except Exception as e:
                    print(f"#{aid}: ошибка записи: {e}")
                    errors += 1
            else:
                fixed += 1
                print(f"#{aid}: будет обновлено — {(a.get('alert_title') or '')[:60]}")
        if len(alerts) < 100:
            break
        page += 1
    print(f"\nИтог: {'обновлено' if APPLY else 'кандидатов'} {fixed}, пропущено {skipped}, ошибок {errors}")


if __name__ == "__main__":
    main()
