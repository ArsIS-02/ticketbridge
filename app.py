#!/usr/bin/env python3
"""TicketBridge — мост «Graylog → GLPI»: High-алерты становятся тикетами.

Graylog HTTP-уведомление шлёт JSON события на POST /hook?key=<TB_KEY>;
мост создаёт тикет в GLPI через REST API и логирует действие в Graylog (GELF).

ENV:
  TB_PORT         — порт (8099)
  TB_KEY          — секрет в URL вебхука (обязателен в бою)
  TB_GLPI_URL     — база GLPI (http://192.168.1.149/glpi)
  TB_GLPI_APP_TOKEN, TB_GLPI_USER_TOKEN — токены API GLPI
  TB_GELF_HOST/PORT — 127.0.0.1:12206
  TB_HOMEWIKI     — база HomeWiki (https://homewiki.apps.monitoring.test)
  TB_BLOCKBOARD   — база BlockBoard (https://blockboard.apps.monitoring.test)
  TB_CORR_WINDOW  — окно корреляции в секундах (1800): алерты одного хоста
                    за окно дополняют открытый тикет, а не плодят новые
  TB_CLOSE_AFTER  — автозакрытие в секундах (86400): если по хосту нет новых
                    алертов сутки, тикет закрывается комментарием (цикл MTTR)
  TB_RECOVERY_RE  — regex события восстановления (agent_recovered|вернулся):
                    такое событие сразу закрывает открытый тикет хоста
  TB_STATE_DB     — SQLite соответствий хост→тикет (state.db рядом с app.py)
"""
import gzip
import html
import json
import os
import re
import socket
import sqlite3
import ssl
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(os.environ.get("TB_PORT", "8099"))
KEY = os.environ.get("TB_KEY", "dev-key")
GLPI = os.environ.get("TB_GLPI_URL", "http://192.168.1.149/glpi").rstrip("/")
APP_TOKEN = os.environ.get("TB_GLPI_APP_TOKEN", "")
USER_TOKEN = os.environ.get("TB_GLPI_USER_TOKEN", "")
GELF_HOST = os.environ.get("TB_GELF_HOST", "127.0.0.1")
GELF_PORT = int(os.environ.get("TB_GELF_PORT", "12206"))
HOMEWIKI = os.environ.get("TB_HOMEWIKI", "https://homewiki.apps.monitoring.test").rstrip("/")
BLOCKBOARD = os.environ.get("TB_BLOCKBOARD", "https://blockboard.apps.monitoring.test").rstrip("/")
HOST = socket.gethostname()
WINDOW = int(os.environ.get("TB_CORR_WINDOW", "1800"))
CLOSE_AFTER = int(os.environ.get("TB_CLOSE_AFTER", "86400"))
RECOVERY_RE = re.compile(os.environ.get("TB_RECOVERY_RE", r"agent_recovered|вернулся|recovered"), re.I)
STATE_DB = os.environ.get("TB_STATE_DB",
                          os.path.join(os.path.dirname(os.path.abspath(__file__)), "state.db"))
CORR_LOCK = threading.Lock()
CLOSED_STATUSES = {5, 6}   # GLPI: 5=решён, 6=закрыт

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

URGENCY = {3: 5, 2: 3, 1: 1}   # Graylog priority -> GLPI urgency


class GlpiError(Exception):
    pass


class Glpi:
    """Минимальный клиент GLPI REST API."""

    def __init__(self, base=GLPI, app_token=APP_TOKEN, user_token=USER_TOKEN):
        self.base = base
        self.app_token = app_token
        self.user_token = user_token
        self.session = None

    def _req(self, path, body=None, headers=None, method=None):
        h = {"Content-Type": "application/json", "App-Token": self.app_token}
        if self.session:
            h["Session-Token"] = self.session
        h.update(headers or {})
        data = json.dumps(body).encode() if body is not None else None
        if method is None:
            method = "POST" if data else "GET"
        req = urllib.request.Request(self.base + "/apirest.php" + path, data=data,
                                     headers=h, method=method)
        try:
            with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            raise GlpiError(f"GLPI {path}: HTTP {e.code} {e.read()[:200]!r}") from e

    def __enter__(self):
        self.session = self._req("/initSession",
                                 headers={"Authorization": f"user_token {self.user_token}"}
                                 )["session_token"]
        return self

    def __exit__(self, *a):
        try:
            if self.session:
                self._req("/killSession")
        finally:
            self.session = None

    def create_ticket(self, name, content, urgency=3):
        r = self._req("/Ticket", {"input": {"name": name[:250], "content": content,
                                            "urgency": urgency}})
        return r.get("id") if isinstance(r, dict) else r

    def get_ticket(self, tid):
        return self._req(f"/Ticket/{tid}")

    def add_followup(self, tid, content):
        """Комментарий к тикету (GLPI 10: ITILFollowup, старые: Followup)."""
        body = {"input": {"itemtype": "Ticket", "items_id": tid, "content": content}}
        try:
            return self._req(f"/Ticket/{tid}/ITILFollowup", body)
        except GlpiError:
            return self._req(f"/Ticket/{tid}/Followup", body)

    def close_ticket(self, tid, comment):
        """Комментарий + статус «закрыт» (6)."""
        self.add_followup(tid, comment)
        return self._req(f"/Ticket/{tid}", {"input": {"status": 6}}, method="PUT")


def esc(s):
    return html.escape(str(s))


def compose_ticket(event):
    """(тема, HTML-описание, urgency) из события Graylog."""
    msg = event.get("message") or "событие Graylog"
    f = event.get("fields") or {}
    rows = "".join(f"<tr><td style='color:#888'>{esc(k)}</td><td>{esc(v)}</td></tr>"
                   for k, v in list(f.items())[:15])
    links = [f"<a href='{HOMEWIKI}/rules/{event.get('event_definition_id')}'>📖 Разбор в HomeWiki</a>"]
    ioc, itype = f.get("ioc"), f.get("ioc_type")
    if ioc and itype in ("ip", "domain"):
        links.append(f"<a href='{BLOCKBOARD}/?block={esc(ioc)}&reason=Graylog'>🛡 Заблокировать {esc(ioc)}</a>")
    if f.get("tl_report"):
        links.append(f"<a href='{esc(f['tl_report'])}'>📊 Отчёт TrafficLens</a>")
    content = (f"<b>{esc(msg)}</b><br>Время: {esc(event.get('timestamp'))}<br>"
               f"Приоритет: {esc(event.get('priority'))}<br><br>"
               f"<table>{rows}</table><br>" + " · ".join(links))
    prio = int(event.get("priority") or 2)
    return f"[Graylog] {msg}"[:250], content, URGENCY.get(prio, 3)


def send_gelf(short, **fields):
    msg = {"version": "1.1", "host": HOST, "short_message": short,
           "timestamp": time.time(), "level": 4}
    msg.update({f"_{k}": v for k, v in fields.items()})
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(gzip.compress(json.dumps(msg, ensure_ascii=False).encode()), (GELF_HOST, GELF_PORT))
    sock.close()


def corr_key(event):
    """Ключ корреляции: хост-источник алерта (нормализованный)."""
    f = event.get("fields") or {}
    for cand in (f.get("host"), f.get("source"), event.get("key"), event.get("source")):
        if cand:
            return str(cand).strip().lower()
    return "unknown"


def state_db():
    con = sqlite3.connect(STATE_DB)
    con.execute("""CREATE TABLE IF NOT EXISTS incidents(
        corr_key TEXT PRIMARY KEY, ticket_id INTEGER,
        first_ts REAL, last_ts REAL, cnt INTEGER, last_msg TEXT)""")
    return con


def is_recovery(event):
    """Событие восстановления («хост вернулся», agent_recovered и т.п.)."""
    f = event.get("fields") or {}
    hay = " ".join(str(x) for x in (
        event.get("message"), event.get("key"), f.get("hr_event"), f.get("event"),
        (event.get("event_definition_title") or "")))
    return bool(RECOVERY_RE.search(hay))


def close_incident(key, comment, now=None):
    """Закрыть открытый тикет по ключу корреляции. Возвращает id или None."""
    now = now or time.time()
    with CORR_LOCK:
        con = state_db()
        row = con.execute(
            "SELECT ticket_id, first_ts, cnt FROM incidents WHERE corr_key=?",
            (key,)).fetchone()
        if not row or key == "unknown":
            con.close()
            return None
        tid, first_ts, cnt = row
        try:
            with Glpi() as g:
                t = g.get_ticket(tid)
                if int(t.get("status", 6)) in CLOSED_STATUSES:
                    raise GlpiError("уже закрыт")
                g.close_ticket(tid, comment + (
                    f"<br><br>Инцидент по <b>{esc(key)}</b>: "
                    f"{cnt} алерт(ов) за {(now - first_ts) / 3600:.1f} ч. "
                    f"Закрыт автоматически TicketBridge."))
        except GlpiError:
            con.close()
            return None
        con.execute("DELETE FROM incidents WHERE corr_key=?", (key,))
        con.commit()
        con.close()
    return tid


def sweeper():
    """Раз в 30 минут закрывает инциденты без новых алертов дольше CLOSE_AFTER."""
    while True:
        time.sleep(1800)
        try:
            now = time.time()
            con = state_db()
            stale = [r[0] for r in con.execute(
                "SELECT corr_key FROM incidents WHERE last_ts < ?", (now - CLOSE_AFTER,))]
            con.close()
            for key in stale:
                tid = close_incident(
                    key, f"<b>Автозакрытие:</b> новых алертов по хосту нет "
                         f"{CLOSE_AFTER // 3600} ч.", now)
                if tid:
                    send_gelf(f"TicketBridge: тикет #{tid} автозакрыт по TTL ({key})",
                              tool="ticketbridge", tb_event="autoclose",
                              ticket_id=tid, corr=key)
        except Exception:
            pass   # фоновый поток не должен умирать


def handle_event(event):
    """Создать тикет GLPI из события Graylog или дополнить открытый инцидент.

    Алерты одного хоста в пределах окна TB_CORR_WINDOW дополняют уже
    открытый тикет комментарием (таймлайн), а не создают новый.
    Событие восстановления (agent_recovered и т.п.) закрывает тикет.
    """
    key = corr_key(event)
    now = time.time()
    msg = (event.get("message") or "событие Graylog")
    if is_recovery(event) and key != "unknown":
        tid = close_incident(
            key, f"<b>Восстановление:</b> {esc(msg)} "
                 f"({esc(event.get('timestamp') or '')}).", now)
        if tid:
            send_gelf(f"TicketBridge: тикет #{tid} закрыт — хост {key} восстановлен",
                      tool="ticketbridge", tb_event="closed_recovery",
                      ticket_id=tid, corr=key)
            return tid
        # некому закрывать — восстановление без открытого инцидента игнорируем
        send_gelf(f"TicketBridge: восстановление без открытого тикета ({key})",
                  tool="ticketbridge", tb_event="recovery_skip", corr=key)
        return None
    with CORR_LOCK:
        con = state_db()
        row = con.execute(
            "SELECT ticket_id, first_ts, last_ts, cnt FROM incidents WHERE corr_key=?",
            (key,)).fetchone()
        if row and key != "unknown" and now - row[2] <= WINDOW:
            tid, cnt = row[0], row[3]
            try:
                with Glpi() as g:
                    t = g.get_ticket(tid)
                    if int(t.get("status", 6)) in CLOSED_STATUSES:
                        raise GlpiError(f"тикет {tid} закрыт")
                    fup = (f"<b>+ {esc(msg)}</b><br>Время: {esc(event.get('timestamp'))}<br>"
                           f"Продолжение инцидента по хосту <b>{esc(key)}</b> — "
                           f"алерт №{cnt + 1} за последние {WINDOW // 60} мин.")
                    g.add_followup(tid, fup)
                con.execute("UPDATE incidents SET last_ts=?, cnt=cnt+1, last_msg=? WHERE corr_key=?",
                            (now, msg[:200], key))
                con.commit()
                con.close()
                send_gelf(f"TicketBridge: тикет #{tid} дополнен ({key}: {msg[:80]})",
                          tool="ticketbridge", tb_event="followup",
                          ticket_id=tid, corr=key)
                return tid
            except GlpiError:
                pass   # тикет закрыт или GLPI недоступен — заводим новый
        name, content, urgency = compose_ticket(event)
        with Glpi() as g:
            tid = g.create_ticket(name, content, urgency)
        con.execute("""INSERT OR REPLACE INTO incidents
                       (corr_key, ticket_id, first_ts, last_ts, cnt, last_msg)
                       VALUES(?,?,?,?,1,?)""", (key, tid, now, now, msg[:200]))
        con.commit()
        con.close()
    send_gelf(f"TicketBridge: тикет GLPI #{tid} — {name[:120]}",
              tool="ticketbridge", tb_event="ticket", ticket_id=tid,
              corr=key, alert=msg[:200])
    return tid


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        p = urlparse(self.path)
        if p.path != "/hook":
            return self._json({"error": "not found"}, 404)
        if parse_qs(p.query).get("key", [""])[0] != KEY:
            return self._json({"error": "bad key"}, 403)
        n = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._json({"error": "bad json"}, 400)
        event = body.get("event") or body  # Graylog шлёт {"event": {...}}
        try:
            tid = handle_event(event)
        except GlpiError as e:
            return self._json({"ok": False, "error": str(e)[:200]}, 502)
        self._json({"ok": True, "ticket_id": tid})

    def do_GET(self):
        if urlparse(self.path).path == "/health":
            return self._json({"ok": True, "glpi": GLPI})
        self._json({"error": "not found"}, 404)

    def _json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    threading.Thread(target=sweeper, daemon=True).start()
    print(f"TicketBridge: http://0.0.0.0:{PORT}/hook (GLPI: {GLPI}, "
          f"автозакрытие после {CLOSE_AFTER // 3600} ч тишины)")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
