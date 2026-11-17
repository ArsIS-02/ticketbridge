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
  TB_HOSTDECK_URL — база HostDeck (http://127.0.0.1:8080) для обогащения
                    алертов IRIS активами; пустой токен отключает обогащение
  TB_HOSTDECK_TOKEN — токен экспорта HostDeck (HOSTDECK_EXPORT_TOKEN)
  TB_HOSTDECK_TTL — кеш инвентаря HostDeck в секундах (300)
  TB_IRIS_CORR    — корреляция алертов IRIS (1/0, по умолчанию 1):
                    повторные срабатывания того же правила по тому же активу
                    обогащают открытый алерт комментарием, а не плодят новые
  TB_SCORE_WINDOW — окно корреляции и скоринга в секундах (86400)
  TB_SCORE_THRESHOLD — порог скора для автоэскалации алерта в кейс (100)
  TB_SCORE_HIGH/MEDIUM/LOW — вес срабатывания по приоритету Graylog (50/20/5)
  TB_SCORE_MITRE_MULT — множитель веса для правил с MITRE-техникой (2)
"""
import base64
import csv
import gzip
import html
import io
import json
import os
import re
import socket
import sqlite3
import ssl
import threading
import time
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote

import iris_evidence_pack

PORT = int(os.environ.get("TB_PORT", "8099"))
EVIDENCE_PACK = os.environ.get("TB_EVIDENCE_PACK", "1").lower() not in ("0", "false", "no")
KEY = os.environ.get("TB_KEY", "dev-key")
GLPI = os.environ.get("TB_GLPI_URL", "http://192.168.1.149/glpi").rstrip("/")
APP_TOKEN = os.environ.get("TB_GLPI_APP_TOKEN", "")
USER_TOKEN = os.environ.get("TB_GLPI_USER_TOKEN", "")
GELF_HOST = os.environ.get("TB_GELF_HOST", "127.0.0.1")
GELF_PORT = int(os.environ.get("TB_GELF_PORT", "12206"))
HOMEWIKI = os.environ.get("TB_HOMEWIKI", "https://homewiki.apps.monitoring.test").rstrip("/")
BLOCKBOARD = os.environ.get("TB_BLOCKBOARD", "https://blockboard.apps.monitoring.test").rstrip("/")
GRAYLOG = os.environ.get("TB_GRAYLOG_URL", "https://graylog.apps.monitoring.test").rstrip("/")
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

IRIS = os.environ.get("TB_IRIS_URL", "").rstrip("/")   # https://iris.apps.monitoring.test
IRIS_KEY = os.environ.get("TB_IRIS_KEY", "")
IRIS_SEVERITY = {3: 5, 2: 1, 1: 4}   # Graylog priority -> IRIS severity (High/Medium/Low)
ZABBIX_IRIS_SEVERITY = {0: 4, 1: 4, 2: 4, 3: 1, 4: 5, 5: 5}
ZABBIX_HOMEWIKI = os.environ.get(
    "TB_ZABBIX_HOMEWIKI", HOMEWIKI + "/rules/art-zabbix-graylog-iris")
IRIS_API_PATH = os.environ.get("TB_IRIS_API_PATH", "/alerts/add")
if not IRIS_API_PATH.startswith("/") or IRIS_API_PATH.startswith("//"):
    raise ValueError("TB_IRIS_API_PATH must be an absolute path on the IRIS host")

# --- Корреляция и скоринг алертов IRIS (по практикам SOAR Security Vision) ---
IRIS_CORR = os.environ.get("TB_IRIS_CORR", "1").lower() not in ("0", "false", "no")
SCORE_WINDOW = int(os.environ.get("TB_SCORE_WINDOW", "86400"))
SCORE_THRESHOLD = float(os.environ.get("TB_SCORE_THRESHOLD", "100"))
SCORE_BY_PRIORITY = {
    3: float(os.environ.get("TB_SCORE_HIGH", "50")),
    2: float(os.environ.get("TB_SCORE_MEDIUM", "20")),
    1: float(os.environ.get("TB_SCORE_LOW", "5")),
}
SCORE_MITRE_MULT = float(os.environ.get("TB_SCORE_MITRE_MULT", "2"))
CASE_SUPPRESSION = int(os.environ.get("TB_CASE_SUPPRESSION", "86400"))
CASE_REOPEN_MIN_WEIGHT = float(os.environ.get("TB_CASE_REOPEN_MIN_WEIGHT", "50"))
CASE_EVIDENCE_INTERVAL = int(os.environ.get("TB_CASE_EVIDENCE_INTERVAL", "3600"))
IRIS_OPEN_STATUSES = {1, 2, 3, 4, 5, 8}   # всё, кроме Closed(6) и Merged(7)
_MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _load_rule_weights():
    """Точечные веса правил из TB_RULE_WEIGHTS (JSON-объект).

    Ключ — точный event_definition_id ИЛИ префикс заголовка правила
    («CANARY - », «HEALTH - Тишина» …); значение — вес срабатывания,
    заменяющий вес по приоритету. При ошибке парсинга — пустая карта,
    скоринг продолжает работать по приоритетам.
    """
    raw = os.environ.get("TB_RULE_WEIGHTS", "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return {str(k): float(v) for k, v in data.items()}
    except (ValueError, TypeError, AttributeError):
        return {}


RULE_WEIGHTS = _load_rule_weights()


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


def http_url(value):
    """Вернуть только абсолютную HTTP(S)-ссылку, безопасную для HTML."""
    value = str(value or "").strip()
    parsed = urlparse(value)
    return value if parsed.scheme in ("http", "https") and parsed.netloc else ""


def zabbix_runbook(fields):
    """Рунбук из поля/тега Zabbix; иначе общая статья интеграции."""
    for key in ("runbook", "zabbix_runbook", "zabbix_trigger_url"):
        url = http_url(fields.get(key))
        if url:
            return url
    raw_tags = fields.get("zabbix_tags_json")
    try:
        tags = json.loads(raw_tags) if isinstance(raw_tags, str) else raw_tags
        if isinstance(tags, dict):
            url = http_url(tags.get("runbook"))
            if url:
                return url
        elif isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, dict) and tag.get("tag") == "runbook":
                    url = http_url(tag.get("value"))
                    if url:
                        return url
    except (TypeError, ValueError):
        pass
    return ZABBIX_HOMEWIKI


def zabbix_iris_severity(fields, graylog_priority):
    """Важность Zabbix → IRIS; обычные Graylog-алерты не изменяются."""
    try:
        zabbix_priority = int(float(str(fields["zabbix_nseverity"]).strip()))
    except (KeyError, TypeError, ValueError):
        return IRIS_SEVERITY.get(graylog_priority, 1)
    return ZABBIX_IRIS_SEVERITY.get(zabbix_priority,
                                    IRIS_SEVERITY.get(graylog_priority, 1))


def compose_ticket(event):
    """(тема, HTML-описание, urgency) из события Graylog."""
    msg = event.get("message") or "событие Graylog"
    f = event.get("fields") or {}
    is_zabbix = bool(str(f.get("zabbix_event_id") or "").strip())
    # Убираем из текста служебные вставки: JSON-теги Zabbix и голые URL —
    # ссылки ниже добавляются отдельными кликабельными строками.
    msg_clean = re.sub(r'\[\{"tag".*?\}\]', '', msg, flags=re.S)
    msg_clean = re.sub(r'https?://\S+', '', msg_clean)
    msg_clean = re.sub(r'\s*\|\s*(\|\s*)+', ' | ', msg_clean).strip(' |')
    # Поля, которые не показываем в таблице (дублируют ссылки/JSON выше).
    skip_fields = {"zabbix_tags_json", "zabbix_url", "tl_report", "runbook",
                   "zabbix_runbook", "zabbix_trigger_url", "ioc", "ioc_type"}
    rows = "".join(f"<tr><td style='color:#888'>{esc(k)}</td><td>{esc(v)}</td></tr>"
                   for k, v in list(f.items())[:25]
                   if k not in skip_fields and len(str(v)) <= 300)
    links, seen_urls = [], set()

    def add_link(url, label):
        url = http_url(url)
        if url and url not in seen_urls:
            seen_urls.add(url)
            links.append(f"<a href='{esc(url)}'>{label}</a>")

    add_link(f"{HOMEWIKI}/rules/{event.get('event_definition_id')}",
             "📖 Разбор в HomeWiki")
    if is_zabbix:
        add_link(f.get("zabbix_url"), "🚨 Событие Zabbix")
        add_link(graylog_replay_url(event), "🔎 Replay Search в Graylog")
        add_link(zabbix_runbook(f), "📖 Рунбук в HomeWiki")
    ioc, itype = f.get("ioc"), f.get("ioc_type")
    if ioc and itype in ("ip", "domain"):
        links.append(f"<a href='{BLOCKBOARD}/?block={esc(ioc)}&reason=Graylog'>🛡 Заблокировать {esc(ioc)}</a>")
    add_link(f.get("tl_report"), "📊 Отчёт TrafficLens")
    links_html = "<br>".join(links)
    content = (f"<b>{esc(msg_clean)}</b><br>Время: {esc(event.get('timestamp'))}<br>"
               f"Приоритет: {esc(event.get('priority'))}<br><br>"
               f"<table>{rows}</table><br>{links_html}")
    prio = int(event.get("priority") or 2)
    if is_zabbix:
        trigger = str(f.get("zabbix_trigger_name") or
                      f.get("zabbix_trigger_description") or msg_clean).strip()
        host = str(f.get("host") or "").strip()
        title = f"[Zabbix] {trigger}" + (f" — {host}" if host else "")
    else:
        title = f"[Graylog] {msg}"
    return title[:250], content, URGENCY.get(prio, 3)


def graylog_replay_url(event):
    """Replay Search конкретного события; без id — общая очередь Graylog."""
    base = GRAYLOG.rstrip("/")
    event_id = event.get("id")
    if not event_id:
        return f"{base}/alerts"
    return f"{base}/alerts/{quote(str(event_id), safe='')}/replay-search"


IRIS_LOCK = threading.Lock()

# --- Обогащение алертов IRIS активами из HostDeck --------------------------
# ID типов активов IRIS (таблица assets_type)
ASSET_TYPE_ACCOUNT = 1
ASSET_TYPE_AD_ACCOUNT = 18  # Windows Account - AD
ASSET_TYPE_LINUX_SERVER = 3
ASSET_TYPE_LINUX_COMPUTER = 4
ASSET_TYPE_LINUX_ACCOUNT = 5
ASSET_TYPE_MAC = 6
ASSET_TYPE_WINDOWS = 9
ASSET_TYPE_WINDOWS_DC = 11
ASSET_TYPE_ROUTER = 12
# ID типов IOC IRIS (таблица ioc_type)
IOC_TYPE_IP_ANY = 76

HOSTDECK = os.environ.get("TB_HOSTDECK_URL", "http://127.0.0.1:8080").rstrip("/")
HOSTDECK_TOKEN = os.environ.get("TB_HOSTDECK_TOKEN", "")
HOSTDECK_TTL = int(os.environ.get("TB_HOSTDECK_TTL", "300"))

GL_TOKEN = os.environ.get("TB_GRAYLOG_TOKEN", "")
_HD_CACHE = {"ts": 0.0, "by_ip": {}, "by_name": {}}
HD_LOCK = threading.Lock()
_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IP_FIND_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# поля события Graylog, где ищем адреса, имена хостов и учётные записи
_ASSET_IP_KEYS = {"srcip", "dstip", "source_ip", "agent_ip", "gl2_remote_ip",
                  "ip", "src", "dst"}
_ASSET_HOST_KEYS = {"source", "host", "hostname", "node", "device", "agent_name"}
_ASSET_USER_KEYS = {"user", "username", "acct", "account", "suser",
                    "winlog_event_data_targetusername"}
_USER_BAD_SUFFIX = (".service", ".timer", ".socket", ".mount", ".target",
                    ".scope")
_USER_BAD_NAMES = {"unknown", "system", "local", "network"}


def _is_valid_user(u):
    """Отсев мусора в учётках: systemd-юниты, числовые uid, системные имена."""
    ul = u.strip().lower()
    return (bool(ul) and not ul.endswith(_USER_BAD_SUFFIX)
            and not ul.isdigit() and ul not in _USER_BAD_NAMES)


def hostdeck_lookup():
    """Карты ip→info и name→info из экспорта HostDeck; кеш TB_HOSTDECK_TTL сек.

    При любой ошибке возвращает последний кеш (или пустые карты):
    обогащение активами никогда не ломает основной поток Graylog→IRIS.
    """
    if not HOSTDECK_TOKEN:
        return _HD_CACHE["by_ip"], _HD_CACHE["by_name"]
    now = time.time()
    with HD_LOCK:
        if now - _HD_CACHE["ts"] < HOSTDECK_TTL:
            return _HD_CACHE["by_ip"], _HD_CACHE["by_name"]
        by_ip, by_name = {}, {}
        try:
            for key, dest in (("ip", by_ip), ("name", by_name)):
                req = urllib.request.Request(
                    f"{HOSTDECK}/api/export/hosts.csv?key={key}&header=0",
                    headers={"X-Hostdeck-Token": HOSTDECK_TOKEN})
                with urllib.request.urlopen(req, timeout=10, context=CTX) as r:
                    text = r.read().decode("utf-8", "replace")
                for row in csv.reader(io.StringIO(text)):
                    if len(row) < 4 or not row[0].strip():
                        continue
                    dest[row[0].strip().lower()] = {
                        "name": row[1].strip(), "os": row[2].strip(),
                        "profile": row[3].strip()}
            _HD_CACHE.update(ts=now, by_ip=by_ip, by_name=by_name)
        except Exception as e:
            send_gelf(f"TicketBridge: HostDeck недоступен, обогащение по кешу: {e}",
                      tool="ticketbridge", tb_event="hostdeck_error")
        return _HD_CACHE["by_ip"], _HD_CACHE["by_name"]


def _asset_type_for(info):
    """Тип актива IRIS по данным HostDeck (ОС, профиль, имя)."""
    name = (info.get("name") or "").lower()
    os_ = (info.get("os") or "").lower()
    profile = (info.get("profile") or "").lower()
    if "keenetic" in name or "router" in name:
        return ASSET_TYPE_ROUTER
    if name.startswith("dc.") or profile == "dc":
        return ASSET_TYPE_WINDOWS_DC
    if "mac" in os_ or "mac" in name:
        return ASSET_TYPE_MAC
    if "win" in os_ or "windows" in name or name.startswith(("w10", "w11")):
        return ASSET_TYPE_WINDOWS
    if os_.startswith("linux"):
        workstation = profile in {"laptop", "workstation", "desktop"} or "workstation" in name
        return ASSET_TYPE_LINUX_COMPUTER if workstation else ASSET_TYPE_LINUX_SERVER
    return ASSET_TYPE_LINUX_SERVER if profile == "server" else ASSET_TYPE_LINUX_COMPUTER


def _graylog_sample(event, limit=5):
    """До 5 исходных сообщений события через replay_info (legacy absolute search)."""
    ri = event.get("replay_info") or {}
    q, frm, to = ri.get("query"), ri.get("timerange_start"), ri.get("timerange_end")
    if not (GL_TOKEN and q and frm and to):
        return []
    params = {"query": q, "from": frm, "to": to, "limit": str(limit),
              "fields": "source,gl2_remote_ip,srcip,dstip,user,acct,username,agent_name"}
    streams = ri.get("streams") or []
    if streams:
        params["filter"] = "streams:" + ",".join(streams)
    url = GRAYLOG + "/api/search/universal/absolute?" + urllib.parse.urlencode(params)
    auth = base64.b64encode((GL_TOKEN + ":token").encode()).decode()
    req = urllib.request.Request(url, headers={
        "Authorization": "Basic " + auth, "X-Requested-By": "ticketbridge"})
    try:
        with urllib.request.urlopen(req, timeout=10, context=CTX) as r:
            text = r.read().decode("utf-8", "replace")
        return list(csv.DictReader(io.StringIO(text)))
    except Exception:
        return []


def collect_observables(event):
    """(alert_assets, alert_iocs) из полей события Graylog.

    Адреса и имена, известные HostDeck, становятся активами IRIS; неизвестные
    IP — IOC (ip-any). Учётные записи из полей user/acct/... — активы Account.
    Максимум 10 активов и 10 IOC на алерт.
    """
    f = event.get("fields") or {}
    by_ip, by_name = hostdeck_lookup()
    ips, names, users = set(), set(), set()
    for k, v in f.items():
        if not isinstance(v, str):
            continue
        kl = k.lower()
        if kl in _ASSET_IP_KEYS:
            ips.update(x for x in _IP_FIND_RE.findall(v))
        elif kl in _ASSET_HOST_KEYS:
            val = v.strip()
            if _IP_RE.match(val):
                ips.add(val)
            elif re.match(r"^[A-Za-z0-9_.-]{2,64}$", val):
                names.add(val.lower())
        elif kl in _ASSET_USER_KEYS:
            val = v.strip()
            if (re.match(r"^[A-Za-z0-9_.@\\-]{2,64}$", val)
                    and not _IP_RE.match(val) and _is_valid_user(val)):
                users.add(val)
    src = str(event.get("source") or "").strip()
    if _IP_RE.match(src):
        ips.add(src)
    elif re.match(r"^[A-Za-z0-9_.-]{2,64}$", src):
        names.add(src.lower())

    # Текстовый разбор: события Graylog несут IP/имена/учётки внутри текста
    # (fields.event, message), а не в структурированных полях.
    _GENERIC = {"server", "user", "host", "node"}
    text = " ".join(str(t) for t in
                    (f.get("event"), event.get("message"), event.get("key")) if t)
    if text:
        tl = text.lower()
        ips.update(x for x in _IP_FIND_RE.findall(text)
                   if not x.startswith(("0.", "255.", "127.")))
        for nm in by_name:
            if len(nm) < 5 or nm in _GENERIC:
                continue
            if re.search(r"(?<![\w.-])" + re.escape(nm) + r"(?![\w.-])", tl):
                names.add(nm)
        for m in re.finditer(
                r'(?:acct|user|username|login|account)[=:]"?([A-Za-z0-9_.@\\-]{2,32})"?',
                text, re.I):
            u = m.group(1)
            if _is_valid_user(u):
                users.add(u)

    assets, iocs = [], []

    def add_asset(name, type_id, ip="", info=None, desc=""):
        for a in assets:
            if a["asset_name"].lower() == name.lower():
                return
        asset = {"asset_name": name, "asset_type_id": type_id}
        if ip:
            asset["asset_ip"] = ip
        if info is not None:
            parts = [p for p in (info.get("os"), info.get("profile")) if p]
            desc = "HostDeck" + (": " + " / ".join(parts) if parts else "")
        if desc:
            asset["asset_description"] = desc
        assets.append(asset)

    for ip in sorted(ips):
        info = by_ip.get(ip.lower())
        if info:
            add_asset(info["name"], _asset_type_for(info), ip, info=info)
        else:
            iocs.append({"ioc_value": ip, "ioc_type_id": IOC_TYPE_IP_ANY})
    for nm in sorted(names):
        info = by_name.get(nm)
        if info:
            add_asset(info["name"], _asset_type_for(info), info=info)
    if not assets and not iocs:
        for row in _graylog_sample(event):
            srcm = (row.get("source") or "").strip()
            if srcm.lower() in by_name:
                info = by_name[srcm.lower()]
                add_asset(info["name"], _asset_type_for(info), info=info)
            elif _IP_RE.match(srcm):
                info = by_ip.get(srcm.lower())
                if info:
                    add_asset(info["name"], _asset_type_for(info), srcm, info=info)
                else:
                    ips.add(srcm)
            for k in ("gl2_remote_ip", "srcip", "dstip"):
                v = (row.get(k) or "").strip()
                if _IP_RE.match(v) and not v.startswith(("0.", "127.")):
                    ips.add(v)
            for k in ("user", "acct", "username"):
                v = (row.get(k) or "").strip()
                if re.match(r"^[A-Za-z0-9_.@\\-]{2,64}$", v) and not _IP_RE.match(v) \
                        and _is_valid_user(v):
                    users.add(v)
        for ip in sorted(ips):
            if any(a.get("asset_ip") == ip for a in assets):
                continue
            info = by_ip.get(ip.lower())
            if info:
                add_asset(info["name"], _asset_type_for(info), ip, info=info)
            else:
                iocs.append({"ioc_value": ip, "ioc_type_id": IOC_TYPE_IP_ANY})
    for user in sorted(users):
        if "\\" in user or user.endswith("$"):
            add_asset(user, ASSET_TYPE_AD_ACCOUNT, desc="Доменная учётная запись AD")
        elif user.strip().lower() in {"root", "redos", "user", "ansible"}:
            add_asset(user, ASSET_TYPE_LINUX_ACCOUNT, desc="Linux-учётная запись из события Graylog")
        else:
            add_asset(user, ASSET_TYPE_ACCOUNT, desc="Учётная запись из события Graylog")
    return assets[:10], iocs[:10]


def _post_iris(payload):
    """Создать алерт IRIS и вернуть (ok, alert_id/ошибка)."""
    try:
        req = urllib.request.Request(
            IRIS + IRIS_API_PATH, method="POST",
            data=json.dumps(payload, ensure_ascii=False).encode(),
            headers={"Authorization": "Bearer " + IRIS_KEY,
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15, context=CTX) as r:
            body = json.loads(r.read().decode())
        data = body.get("data")
        if isinstance(data, dict) and data.get("alert_id") is not None:
            return True, str(data["alert_id"])
        # IRIS v3 возвращает созданный объект напрямую, без конверта v2.
        if body.get("alert_id") is not None:
            return True, str(body["alert_id"])
        if body.get("status") == "success":
            return True, ""
        return False, str(body)[:200]
    except Exception as e:
        return False, str(e)[:200]


def _iris_request(method, path, payload=None):
    """HTTP-запрос к IRIS API v2; возвращает (ok, данные/текст ошибки)."""
    try:
        req = urllib.request.Request(
            IRIS + path, method=method,
            data=json.dumps(payload, ensure_ascii=False).encode()
            if payload is not None else None,
            headers={"Authorization": "Bearer " + IRIS_KEY,
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15, context=CTX) as r:
            body = json.loads(r.read().decode() or b"{}")
        return True, body.get("data", body)
    except Exception as e:
        return False, str(e)[:200]


def _iris_alert_status(alert_id):
    """status_id алерта IRIS или None (ошибка API / алерт удалён)."""
    ok, data = _iris_request("GET", f"/api/v2/alerts/{alert_id}")
    if not ok or not isinstance(data, dict):
        return None
    try:
        return int(data.get("alert_status_id"))
    except (TypeError, ValueError):
        return None


def _iris_add_comment(alert_id, text):
    """Комментарий в таймлайн алерта IRIS."""
    return _iris_request("POST", f"/api/v2/alerts/{alert_id}/comments",
                         {"comment_text": text})


def _iris_escalate(alert_id, case_title, note,
                   tags="graylog,ticketbridge,correlation"):
    """Эскалация алерта в кейс IRIS; возвращает (case_id или None, инфо)."""
    ok, data = _iris_request("POST", f"/api/v2/alerts/escalate/{alert_id}", {
        "case_title": case_title[:250], "note": note, "case_tags": tags,
        "import_as_event": True})
    if ok and isinstance(data, dict) and data.get("case_id") is not None:
        return data["case_id"], ""
    return None, str(data)[:200]


def rule_weight(event):
    """Вес срабатывания: точечный из TB_RULE_WEIGHTS (точный id правила или
    самый длинный префикс заголовка), иначе база по приоритету Graylog;
    множитель ×N за MITRE-технику применяется в любом случае."""
    try:
        prio = int(event.get("priority") or 2)
    except (TypeError, ValueError):
        prio = 2
    w = SCORE_BY_PRIORITY.get(prio, SCORE_BY_PRIORITY[2])
    if RULE_WEIGHTS:
        rule_id = str(event.get("event_definition_id") or "")
        title = str(event.get("event_definition_title") or "")
        if rule_id in RULE_WEIGHTS:
            w = RULE_WEIGHTS[rule_id]
        elif title:
            best = ""
            for prefix, weight in RULE_WEIGHTS.items():
                if len(prefix) > len(best) and title.startswith(prefix):
                    best, w = prefix, weight
    f = event.get("fields") or {}
    hay = " ".join(str(x) for x in (event.get("message"), event.get("key"),
                                    f.get("event"), f.get("tags"),
                                    f.get("mitre"), f.get("mitre_technique"))
                   if x)
    if _MITRE_RE.search(hay):
        w *= SCORE_MITRE_MULT
    return w


def iris_corr_key(event, assets):
    """Ключ корреляции: правило Graylog + главный актив.

    Главный актив — первый не-учётный актив (хост, сеть, ПО); если активов
    нет или все — учётки, берётся первая учётка; иначе хост-источник события.
    """
    rule = str(event.get("event_definition_id")
               or event.get("event_definition_title") or "unknown-rule")
    asset = ""
    for a in assets:
        if a.get("asset_type_id") not in (ASSET_TYPE_ACCOUNT, ASSET_TYPE_AD_ACCOUNT):
            asset = a["asset_name"]
            break
    if not asset and assets:
        asset = assets[0]["asset_name"]
    if not asset:
        asset = corr_key(event)
    return f"{rule}|{asset.strip().lower()}"


def _iris_enrich(alert_id, event, hits, score, weight, assets, iocs):
    """Комментарий-обогащение в таймлайн существующего алерта."""
    lines = [f"🔁 Повторное срабатывание №{hits}: "
             f"{event.get('message') or 'событие Graylog'}",
             f"- Время: {event.get('timestamp') or 'не указано'}",
             f"- Скор: +{weight:g} → **{score:g}** "
             f"(порог эскалации {SCORE_THRESHOLD:g})"]
    new_assets = [a["asset_name"] for a in assets]
    new_iocs = [i["ioc_value"] for i in iocs]
    if new_assets:
        lines.append("- Активы: " + ", ".join(new_assets[:10]))
    if new_iocs:
        lines.append("- IoC: " + ", ".join(new_iocs[:10]))
    url = http_url(graylog_replay_url(event))
    if url:
        lines.append(f"- [Replay Search в Graylog]({url})")
    ok, err = _iris_add_comment(alert_id, "\n".join(lines))
    if not ok:
        send_gelf(f"TicketBridge: не удалось обогатить IRIS алерт "
                  f"#{alert_id}: {err}", tool="ticketbridge",
                  tb_event="iris_enrich_error", iris_alert_id=alert_id)


def _iris_case_state(case_id):
    """Состояние кейса: open/closed; None означает ошибку или неизвестный ответ."""
    ok, data = _iris_request("GET", f"/api/v2/cases/{case_id}")
    if not ok or not isinstance(data, dict):
        return None
    state = data.get("state") if isinstance(data.get("state"), dict) else {}
    name = str(data.get("state_name") or state.get("state_name") or "").strip().lower()
    if name == "closed" or data.get("close_date"):
        return "closed"
    if name or data.get("state_id") is not None or state.get("state_id") is not None:
        return "open"
    return None


def _case_event_date(event):
    """Дата события Graylog в формате IRIS EventSchema, всегда в UTC."""
    raw = str(event.get("timestamp") or "").strip()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        parsed = datetime.now(timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")


def _iris_add_case_event(case_id, event, hits, score, weight, assets, iocs,
                         reopened=False):
    """Событие в default timeline кейса; активы/IOC и replay сохраняются в тексте."""
    prefix = "Кейс переоткрыт по весомому срабатыванию" if reopened else f"Срабатывание №{hits}"
    lines = [f"{prefix}: {event.get('message') or 'событие Graylog'}",
             f"Время: {event.get('timestamp') or 'не указано'}; "
             f"вес +{weight:g}; скор {score:g}"]
    if assets:
        lines.append("Активы: " + ", ".join(a["asset_name"] for a in assets[:10]))
    if iocs:
        lines.append("IoC: " + ", ".join(i["ioc_value"] for i in iocs[:10]))
    replay = http_url(graylog_replay_url(event))
    if replay:
        lines.append("Graylog Replay Search: " + replay)
    payload = {
        "event_title": "\n".join(lines),
        "event_category_id": 1,
        "event_date": _case_event_date(event),
        "event_tz": "+00:00",
        "event_assets": [],
        "event_iocs": [],
        "event_source": "Graylog / TicketBridge",
        "event_tags": "graylog,ticketbridge,correlation",
    }
    ok, info = _iris_request("POST", f"/api/v2/cases/{case_id}/events", payload)
    if not ok:
        send_gelf(f"TicketBridge: не удалось добавить событие кейса #{case_id}: {info}",
                  tool="ticketbridge", tb_event="iris_case_event_error",
                  case_id=case_id)
    return ok


def _attach_case_evidence(case_id, alert_id, event, score, hits):
    """Best-effort снимок доказательств; ошибка не отменяет жизненный цикл кейса."""
    if not EVIDENCE_PACK:
        return False
    try:
        pack = iris_evidence_pack.build_and_attach(
            case_id=case_id, alert_id=alert_id, iris_url=IRIS,
            iris_key=IRIS_KEY, graylog_url=GRAYLOG, graylog_token=GL_TOKEN,
            trigger_event=event, score=score, hits=hits)
        send_gelf(f"TicketBridge: пакет доказательств кейса #{case_id} "
                  f"приложен как {pack['filename']}", tool="ticketbridge",
                  tb_event="iris_evidence_pack", iris_alert_id=alert_id,
                  case_id=case_id, file_id=pack["file_id"],
                  evidence_id=pack["evidence_id"])
        return True
    except Exception as pack_error:
        send_gelf(f"TicketBridge: пакет доказательств кейса #{case_id} "
                  f"не приложен: {pack_error}", tool="ticketbridge",
                  tb_event="iris_evidence_pack_error",
                  iris_alert_id=alert_id, case_id=case_id)
        return False


def _escalate_correlated(alert_id, event, key, score, hits):
    """Эскалация алерта в кейс IRIS при достижении порога скора."""
    asset = key.split("|", 1)[1] if "|" in key else key
    rule = str(event.get("event_definition_title") or key.split("|", 1)[0])
    note = (f"Автоэскалация TicketBridge: скор **{score:g}** ≥ "
            f"{SCORE_THRESHOLD:g} за {SCORE_WINDOW // 3600} ч "
            f"({hits} срабатываний правила по активу `{asset}`).")
    case_id, err = _iris_escalate(alert_id, f"[Корреляция] {rule} — {asset}",
                                  note)
    if case_id:
        _attach_case_evidence(case_id, alert_id, event, score, hits)
        send_gelf(f"TicketBridge: IRIS алерт #{alert_id} эскалирован "
                  f"в кейс #{case_id} ({key}, скор {score:g})",
                  tool="ticketbridge", tb_event="iris_escalated",
                  iris_alert_id=alert_id, case_id=case_id, corr=key,
                  score=score)
    else:
        send_gelf(f"TicketBridge: ОШИБКА эскалации IRIS алерта "
                  f"#{alert_id}: {err}", tool="ticketbridge",
                  tb_event="iris_escalate_error", iris_alert_id=alert_id)
    return case_id


def _update_corr_case(con, key, score, hits, now, escalated, case_id,
                      case_closed_ts, last_evidence_ts):
    con.execute(
        "UPDATE iris_corr SET score=?, hit_count=?, last_ts=?, escalated=?,"
        " case_id=?, case_closed_ts=?, last_evidence_ts=? WHERE corr_key=?",
        (score, hits, now, escalated, case_id, case_closed_ts,
         last_evidence_ts, key))


def _correlated_send(event, payload, assets, iocs):
    """Один жизненный цикл на связку «правило + актив».

    Открытый кейс получает события и свежие доказательства вместо новых алертов.
    После закрытия повторы подавляются на TB_CASE_SUPPRESSION; весомое событие
    может переоткрыть кейс. При неизвестном состоянии кейса дубль не создаётся.
    """
    key = iris_corr_key(event, assets)
    now = time.time()
    weight = rule_weight(event)
    with IRIS_LOCK:
        con = state_db()
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT alert_id, score, hit_count, last_ts, escalated, case_id,"
                " case_closed_ts, last_evidence_ts FROM iris_corr WHERE corr_key=?",
                (key,)).fetchone()
            if row and (now - row[3] <= SCORE_WINDOW or (row[4] and row[5])):
                (alert_id, score, hits, _, escalated, case_id,
                 case_closed_ts, last_evidence_ts) = row
                status = _iris_alert_status(alert_id)

                if escalated and case_id:
                    case_state = _iris_case_state(case_id)
                    if case_state == "open":
                        hits += 1
                        score += weight
                        if status in IRIS_OPEN_STATUSES:
                            _iris_enrich(alert_id, event, hits, score, weight,
                                         assets, iocs)
                        _iris_add_case_event(case_id, event, hits, score, weight,
                                             assets, iocs)
                        if (EVIDENCE_PACK and
                                (last_evidence_ts is None or
                                 now - last_evidence_ts >= CASE_EVIDENCE_INTERVAL)):
                            _attach_case_evidence(case_id, alert_id, event, score, hits)
                            # Ошибку тоже throttle'им: следующая попытка через интервал.
                            last_evidence_ts = now
                        _update_corr_case(con, key, score, hits, now, 1, case_id,
                                          None, last_evidence_ts)
                        con.commit()
                        send_gelf(
                            f"TicketBridge: IRIS кейс #{case_id} обогащён "
                            f"({key}: {hits} сраб., скор {score:g})",
                            tool="ticketbridge", tb_event="iris_case_enriched",
                            iris_alert_id=alert_id, case_id=case_id, corr=key,
                            score=score, hit_count=hits)
                        return True, str(alert_id)

                    if case_state == "closed":
                        case_closed_ts = case_closed_ts or now
                        if now - case_closed_ts <= CASE_SUPPRESSION:
                            if weight < CASE_REOPEN_MIN_WEIGHT:
                                con.execute(
                                    "UPDATE iris_corr SET case_closed_ts=?, last_ts=?"
                                    " WHERE corr_key=?", (case_closed_ts, now, key))
                                con.commit()
                                send_gelf(
                                    f"TicketBridge: повтор по закрытому кейсу #{case_id} "
                                    f"подавлен ({key}, вес {weight:g})",
                                    tool="ticketbridge", tb_event="iris_case_suppressed",
                                    iris_alert_id=alert_id, case_id=case_id, corr=key,
                                    weight=weight)
                                return True, str(alert_id)
                            reopened, info = _iris_request(
                                "POST", f"/api/v2/cases/{case_id}/reopen", {})
                            if not reopened:
                                con.execute(
                                    "UPDATE iris_corr SET case_closed_ts=?, last_ts=?"
                                    " WHERE corr_key=?", (case_closed_ts, now, key))
                                con.commit()
                                send_gelf(
                                    f"TicketBridge: не удалось переоткрыть кейс "
                                    f"#{case_id}: {info}", tool="ticketbridge",
                                    tb_event="iris_case_reopen_error", case_id=case_id,
                                    iris_alert_id=alert_id, corr=key)
                                return False, f"case {case_id} reopen failed: {info}"
                            hits += 1
                            score += weight
                            if status in IRIS_OPEN_STATUSES:
                                _iris_enrich(alert_id, event, hits, score, weight,
                                             assets, iocs)
                            _iris_add_case_event(case_id, event, hits, score, weight,
                                                 assets, iocs, reopened=True)
                            _attach_case_evidence(case_id, alert_id, event, score, hits)
                            last_evidence_ts = now
                            _update_corr_case(con, key, score, hits, now, 1, case_id,
                                              None, last_evidence_ts)
                            con.commit()
                            send_gelf(
                                f"TicketBridge: IRIS кейс #{case_id} переоткрыт "
                                f"по срабатыванию весом {weight:g}",
                                tool="ticketbridge", tb_event="iris_case_reopened",
                                iris_alert_id=alert_id, case_id=case_id, corr=key,
                                score=score, hit_count=hits, weight=weight)
                            return True, str(alert_id)
                        # Подавление истекло: ниже начинается новый жизненный цикл.
                    else:
                        # API не подтвердило состояние: сохраняем case_id и не плодим дубли.
                        send_gelf(f"TicketBridge: состояние кейса #{case_id} неизвестно",
                                  tool="ticketbridge", tb_event="iris_case_state_error",
                                  iris_alert_id=alert_id, case_id=case_id, corr=key)
                        if status in IRIS_OPEN_STATUSES:
                            hits += 1
                            score += weight
                            _iris_enrich(alert_id, event, hits, score, weight,
                                         assets, iocs)
                            _update_corr_case(con, key, score, hits, now, escalated,
                                              case_id, case_closed_ts, last_evidence_ts)
                            con.commit()
                            return True, str(alert_id)
                        con.rollback()
                        return False, f"case {case_id} state unavailable"

                if status in IRIS_OPEN_STATUSES and not (escalated and case_id):
                    hits += 1
                    score += weight
                    _iris_enrich(alert_id, event, hits, score, weight,
                                 assets, iocs)
                    if not escalated and score >= SCORE_THRESHOLD:
                        new_case = _escalate_correlated(alert_id, event, key,
                                                        score, hits)
                        if new_case:
                            escalated, case_id = 1, new_case
                            case_closed_ts = None
                            last_evidence_ts = now
                    _update_corr_case(con, key, score, hits, now, escalated, case_id,
                                      case_closed_ts, last_evidence_ts)
                    con.commit()
                    send_gelf(
                        f"TicketBridge: IRIS алерт #{alert_id} обогащён "
                        f"({key}: {hits} сраб., скор {score:g})",
                        tool="ticketbridge", tb_event="iris_enriched",
                        iris_alert_id=alert_id, corr=key, score=score,
                        hit_count=hits)
                    return True, str(alert_id)
                # Закрытый алерт без активного кейса — новый жизненный цикл.

            ok, info = _post_iris(payload)
            if ok and info:
                escalated, case_id, last_evidence_ts = 0, None, None
                if weight >= SCORE_THRESHOLD:
                    case_id = _escalate_correlated(int(info), event, key,
                                                   weight, 1)
                    escalated = 1 if case_id else 0
                    last_evidence_ts = now if case_id else None
                con.execute(
                    "INSERT OR REPLACE INTO iris_corr"
                    " (corr_key, alert_id, score, hit_count, first_ts, last_ts,"
                    "  escalated, case_id, case_closed_ts, last_evidence_ts)"
                    " VALUES(?,?,?,1,?,?,?,?,?,?)",
                    (key, int(info), weight, now, now, escalated, case_id,
                     None, last_evidence_ts))
            con.commit()
            return ok, info
        except Exception as e:
            con.rollback()
            return False, str(e)[:200]
        finally:
            con.close()


def send_iris(event):
    """Дублирует алерт Graylog в DFIR-IRIS через настроенный API endpoint.

    IRIS v2 использует /alerts/add, IRIS v3 — /api/v2/alerts.
    Для Zabbix один event ID навсегда соответствует одному алерту IRIS;
    соответствие хранится в SQLite и переживает перезапуск TicketBridge.
    Прочие события при TB_IRIS_CORR=1 проходят корреляцию: повторы правила
    по тому же активу обогащают открытый алерт (_correlated_send).
    Не влияет на основной поток: при ошибке только предупреждение в GELF.
    Возвращает (ok, info).
    """
    if not IRIS or not IRIS_KEY:
        return False, "disabled"
    f = event.get("fields") or {}
    zabbix_event_id = str(f.get("zabbix_event_id") or "").strip()
    source_ref = (f"zabbix:{zabbix_event_id}" if zabbix_event_id else
                  str(event.get("event_definition_id") or event.get("key") or ""))
    prio = int(event.get("priority") or 2)
    title, description, _ = compose_ticket(event)
    payload = {
        "alert_title": (title if zabbix_event_id else
                        (event.get("message") or "событие Graylog"))[:250],
        "alert_description": description,
        "alert_source": "Graylog",
        "alert_source_ref": source_ref,
        "alert_source_link": graylog_replay_url(event),
        "alert_severity_id": (zabbix_iris_severity(f, prio) if zabbix_event_id
                              else IRIS_SEVERITY.get(prio, 1)),
        "alert_status_id": 2,   # New
        "alert_source_event_time": event.get("timestamp") or "",
        "alert_tags": "graylog,ticketbridge,zabbix" if zabbix_event_id else "graylog,ticketbridge",
        "alert_customer_id": 1,
        "alert_source_content": event,
    }
    try:
        assets, iocs = collect_observables(event)
    except Exception:
        assets, iocs = [], []
    if assets:
        payload["alert_assets"] = assets
    if iocs:
        payload["alert_iocs"] = iocs
    if not zabbix_event_id:
        if not IRIS_CORR:
            return _post_iris(payload)
        return _correlated_send(event, payload, assets, iocs)

    # IRIS v3 в этой установке игнорирует alert_source_ref при фильтрации
    # списка, поэтому используем постоянное локальное соответствие и блокировку.
    with IRIS_LOCK:
        con = state_db()
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT alert_id FROM iris_dedup WHERE dedup_key=?",
                              (source_ref,)).fetchone()
            if row:
                con.commit()
                send_gelf(f"TicketBridge: повтор Zabbix {zabbix_event_id}, "
                          f"используется существующий IRIS алерт #{row[0]}",
                          tool="ticketbridge", tb_event="iris_duplicate",
                          zabbix_event_id=zabbix_event_id, iris_alert_id=row[0])
                return True, str(row[0])
            ok, info = _post_iris(payload)
            if ok and info:
                con.execute("INSERT INTO iris_dedup(dedup_key, alert_id, created_ts) VALUES(?,?,?)",
                            (source_ref, int(info), time.time()))
            con.commit()
            return ok, info
        except Exception as e:
            con.rollback()
            return False, str(e)[:200]
        finally:
            con.close()


def is_zabbix_recovery(event):
    """RESOLVED от Zabbix закрывает алерт исходного PROBLEM, а не создаёт новый.

    В aggregation-вебхуке Graylog поле статуса может отсутствовать, поэтому
    дополнительно распознаём ID и точный заголовок правила восстановления.
    """
    f = event.get("fields") or {}
    if str(f.get("zabbix_event_status") or "").strip().upper() == "RESOLVED":
        return True
    if not str(f.get("zabbix_event_id") or "").strip():
        return False
    recovery_definition = os.environ.get(
        "TB_ZABBIX_RECOVERY_DEFINITION", "6af4b20861b983feab70ed30")
    title = str(event.get("event_definition_title") or event.get("message") or "")
    return (str(event.get("event_definition_id") or "") == recovery_definition or
            "ZABBIX - Проблема устранена (RESOLVED)" in title)


def close_iris(event):
    """Закрыть алерт IRIS и добавить историю восстановления комментарием.

    Комментарий best-effort: его ошибка журналируется, но не отменяет уже
    успешное закрытие. not_found означает, что PROBLEM здесь не регистрировался.
    """
    if not IRIS or not IRIS_KEY:
        return False, "disabled"
    f = event.get("fields") or {}
    zabbix_event_id = str(f.get("zabbix_event_id") or "").strip()
    if not zabbix_event_id:
        return False, "no_zabbix_event_id"
    source_ref = f"zabbix:{zabbix_event_id}"
    with IRIS_LOCK:
        con = state_db()
        row = con.execute("SELECT alert_id FROM iris_dedup WHERE dedup_key=?",
                          (source_ref,)).fetchone()
        con.close()
        if not row:
            return False, "not_found"
        alert_id = int(row[0])
        try:
            req = urllib.request.Request(
                f"{IRIS}/api/v2/alerts/{alert_id}", method="PUT",
                data=json.dumps({"alert_status_id": 6}).encode(),
                headers={"Authorization": "Bearer " + IRIS_KEY,
                         "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=15, context=CTX) as response:
                response.read()
        except Exception as e:
            return False, str(e)[:200]

        comment = ["✅ Восстановлено автоматически по событию Zabbix RESOLVED.",
                   "", f"- Event ID: `{zabbix_event_id}`",
                   f"- Время восстановления: {event.get('timestamp') or 'не указано'}"]
        if f.get("zabbix_event_duration"):
            comment.append(f"- Длительность проблемы: {f['zabbix_event_duration']}")
        for url, label in ((f.get("zabbix_url"), "Событие Zabbix"),
                           (graylog_replay_url(event), "Replay Search в Graylog"),
                           (zabbix_runbook(f), "Рунбук в HomeWiki")):
            url = http_url(url)
            if url:
                comment.append(f"- [{label}]({url})")
        try:
            req = urllib.request.Request(
                f"{IRIS}/api/v2/alerts/{alert_id}/comments", method="POST",
                data=json.dumps({"comment_text": "\n".join(comment)},
                                ensure_ascii=False).encode(),
                headers={"Authorization": "Bearer " + IRIS_KEY,
                         "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=15, context=CTX) as response:
                response.read()
        except Exception as e:
            send_gelf(f"TicketBridge: IRIS алерт #{alert_id} закрыт, "
                      f"но комментарий восстановления не добавлен: {e}",
                      tool="ticketbridge", tb_event="iris_comment_error",
                      iris_alert_id=alert_id, zabbix_event_id=zabbix_event_id)
        return True, str(alert_id)


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
    con = sqlite3.connect(STATE_DB, timeout=30)
    con.execute("""CREATE TABLE IF NOT EXISTS incidents(
        corr_key TEXT PRIMARY KEY, ticket_id INTEGER,
        first_ts REAL, last_ts REAL, cnt INTEGER, last_msg TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS iris_dedup(
        dedup_key TEXT PRIMARY KEY, alert_id INTEGER NOT NULL, created_ts REAL NOT NULL)""")
    con.execute("""CREATE TABLE IF NOT EXISTS iris_corr(
        corr_key TEXT PRIMARY KEY, alert_id INTEGER NOT NULL,
        score REAL NOT NULL DEFAULT 0, hit_count INTEGER NOT NULL DEFAULT 1,
        first_ts REAL, last_ts REAL,
        escalated INTEGER NOT NULL DEFAULT 0, case_id INTEGER,
        case_closed_ts REAL, last_evidence_ts REAL)""")
    columns = {row[1] for row in con.execute("PRAGMA table_info(iris_corr)")}
    for column in ("case_closed_ts", "last_evidence_ts"):
        if column not in columns:
            con.execute(f"ALTER TABLE iris_corr ADD COLUMN {column} REAL")
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
            # Активные кейсы и период подавления закрытых не удаляем.
            con.execute(
                "DELETE FROM iris_corr WHERE"
                " ((case_id IS NULL OR escalated=0) AND last_ts < ?)"
                " OR (case_closed_ts IS NOT NULL AND case_closed_ts < ?)",
                (now - 2 * SCORE_WINDOW, now - CASE_SUPPRESSION))
            con.commit()
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


def _handle_event(event):
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


def handle_event(event):
    """HIGH → GLPI + IRIS; MEDIUM/LOW → только IRIS; восстановление → закрытие.

    Zabbix RESOLVED закрывает алерт исходного PROBLEM в IRIS по сохранённому
    zabbix_event_id и не затрагивает GLPI. Остальные события восстановления
    по-прежнему закрывают только открытый тикет GLPI.
    """
    if is_zabbix_recovery(event):
        ok, info = close_iris(event)
        f = event.get("fields") or {}
        zabbix_event_id = str(f.get("zabbix_event_id") or "")
        if ok:
            send_gelf(f"TicketBridge: IRIS алерт #{info} закрыт по Zabbix RESOLVED "
                      f"{zabbix_event_id}", tool="ticketbridge", tb_event="iris_closed",
                      iris_alert_id=int(info), zabbix_event_id=zabbix_event_id,
                      corr=corr_key(event))
        else:
            event_type = "iris_recovery_skip" if info == "not_found" else "iris_recovery_error"
            send_gelf(f"TicketBridge: Zabbix RESOLVED {zabbix_event_id}: {info}",
                      tool="ticketbridge", tb_event=event_type,
                      zabbix_event_id=zabbix_event_id, corr=corr_key(event))
        return None

    priority = int(event.get("priority") or 2)
    tid = _handle_event(event) if priority == 3 or is_recovery(event) else None
    if not is_recovery(event):
        ok, info = send_iris(event)
        send_gelf(f"TicketBridge: IRIS {'алерт #' + info if ok else 'ОШИБКА: ' + info}",
                  tool="ticketbridge", tb_event="iris_alert" if ok else "iris_error",
                  corr=corr_key(event), ticket_id=tid or 0)
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
        p = urlparse(self.path)
        if p.path == "/health":
            return self._json({"ok": True, "glpi": GLPI})
        if p.path == "/correlation/status":
            if parse_qs(p.query).get("key", [""])[0] != KEY:
                return self._json({"error": "bad key"}, 403)
            con = state_db()
            rows = con.execute(
                "SELECT corr_key, alert_id, score, hit_count, first_ts, last_ts,"
                " escalated, case_id, case_closed_ts, last_evidence_ts FROM iris_corr"
                " ORDER BY last_ts DESC LIMIT 100").fetchall()
            con.close()
            return self._json({"window_sec": SCORE_WINDOW,
                               "threshold": SCORE_THRESHOLD,
                               "case_suppression_sec": CASE_SUPPRESSION,
                               "case_reopen_min_weight": CASE_REOPEN_MIN_WEIGHT,
                               "case_evidence_interval_sec": CASE_EVIDENCE_INTERVAL,
                               "custom_weights": len(RULE_WEIGHTS),
                               "weights": {str(k): v for k, v in
                                           SCORE_BY_PRIORITY.items()},
                               "rows": [
                    {"corr_key": r[0], "alert_id": r[1], "score": r[2],
                     "hit_count": r[3], "first_ts": r[4], "last_ts": r[5],
                     "escalated": bool(r[6]), "case_id": r[7],
                     "case_closed_ts": r[8], "last_evidence_ts": r[9]}
                    for r in rows]})
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
