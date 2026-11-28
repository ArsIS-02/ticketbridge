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
import velociraptor_evidence
import manual_collection
import alert_collection
import auto_triage_hook
import collection_jobs

PORT = int(os.environ.get("TB_PORT", "8099"))
MAX_BODY_BYTES = int(os.environ.get("TB_MAX_BODY_BYTES", "1048576"))
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


def _load_availability_rules():
    """Явная карта availability definition_id → резервное имя хоста HostDeck.

    Пустое имя означает, что хост берётся из полей события. Заголовки и теги
    нарочно не используются: совпадение по тексту не должно пометить security.
    Ошибка конфигурации безопасно отключает только maintenance-обогащение.
    """
    raw = os.environ.get("TB_AVAILABILITY_RULES", "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return {}
        return {str(k): str(v or "").strip() for k, v in data.items()}
    except (ValueError, TypeError, AttributeError):
        return {}


AVAILABILITY_RULES = _load_availability_rules()


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
                   "zabbix_runbook", "zabbix_trigger_url", "ioc", "ioc_type",
                   "maintenance_active", "maintenance_until", "maintenance_until_iso",
                   "maintenance_reason"}
    rows = "".join(f"<tr><td style='color:#888'>{esc(k)}</td><td>{esc(v)}</td></tr>"
                   for k, v in list(f.items())[:25]
                   if k not in skip_fields and len(str(v)) <= 300)
    maintenance_html = ""
    if maintenance_is_active(event):
        until = f.get("maintenance_until_iso") or f.get("maintenance_until") or "не указан"
        reason = f.get("maintenance_reason") or "Причина не указана"
        maintenance_html = ("<p><b>🛠 Обслуживание HostDeck</b><br>"
                            f"Окончание: {esc(until)}<br>Причина: {esc(reason)}</p>")
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
               f"Приоритет: {esc(event.get('priority'))}<br>{maintenance_html}<br>"
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
_HD_CACHE = {"ts": 0.0, "by_ip": {}, "by_name": {}, "stale": False}
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
    Признак stale запрещает доверять старому maintenance-контексту.
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
                    try:
                        maintenance_until = float(row[9]) if len(row) > 9 and row[9].strip() else 0.0
                    except ValueError:
                        maintenance_until = 0.0
                    dest[row[0].strip().lower()] = {
                        "name": row[1].strip(), "os": row[2].strip(),
                        "profile": row[3].strip(),
                        "maintenance_until": maintenance_until,
                        "maintenance_reason": row[10].strip() if len(row) > 10 else ""}
            _HD_CACHE.update(ts=now, by_ip=by_ip, by_name=by_name, stale=False)
        except Exception as e:
            _HD_CACHE["stale"] = True
            send_gelf(f"TicketBridge: HostDeck недоступен, обогащение по кешу: {e}",
                      tool="ticketbridge", tb_event="hostdeck_error")
        return _HD_CACHE["by_ip"], _HD_CACHE["by_name"]


def with_maintenance_context(event, now=None):
    """Возвращает копию availability-события с активным окном HostDeck.

    Правило должно быть явно перечислено в TB_AVAILABILITY_RULES. Истёкшее окно,
    неизвестный хост, отключённый токен и ошибка HostDeck оставляют событие как есть.
    Security-события и исходный словарь никогда не изменяются.
    """
    rule_id = str(event.get("event_definition_id") or "")
    if not HOSTDECK_TOKEN or rule_id not in AVAILABILITY_RULES:
        return event
    fields = event.get("fields") or {}
    host = (AVAILABILITY_RULES[rule_id] or fields.get("host")
            or fields.get("hr_agent_name") or fields.get("hr_ip")
            or fields.get("source") or event.get("source") or "")
    host = str(host).strip().lower()
    if not host:
        return event
    by_ip, by_name = hostdeck_lookup()
    if _HD_CACHE["stale"]:
        return event
    info = by_name.get(host) or by_ip.get(host)
    if not info:
        return event
    now = time.time() if now is None else now
    try:
        until = float(info.get("maintenance_until") or 0)
    except (TypeError, ValueError):
        return event
    if until <= now:
        return event
    enriched = dict(event)
    enriched_fields = dict(fields)
    enriched_fields.update({
        "maintenance_active": "true",
        "maintenance_until": str(int(until)),
        "maintenance_until_iso": datetime.fromtimestamp(until, timezone.utc).isoformat().replace("+00:00", "Z"),
        "maintenance_reason": str(info.get("maintenance_reason") or "Причина не указана"),
    })
    enriched["fields"] = enriched_fields
    return enriched


def maintenance_is_active(event):
    fields = event.get("fields") or {}
    return str(fields.get("maintenance_active") or "").lower() == "true"


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
                   tags="graylog,ticketbridge,correlation", assets=None):
    """Эскалация алерта в кейс IRIS; возвращает (case_id или None, инфо)."""
    payload = {"case_title": case_title[:250], "note": note, "case_tags": tags,
               "import_as_event": True}
    if assets is not None:
        payload["assets_import_list"] = assets
    ok, data = _iris_request("POST", f"/api/v2/alerts/escalate/{alert_id}", payload)
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
    tags = "graylog,ticketbridge,zabbix" if zabbix_event_id else "graylog,ticketbridge"
    if maintenance_is_active(event):
        tags += ",maintenance,hostdeck"
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
        "alert_tags": tags,
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
    успешное закрытие. Если RESOLVED пришёл раньше PROBLEM, сохраняем его
    ненадолго: send_iris не должен создать запоздалый уже восстановленный алерт.
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
        if not row:
            now = time.time()
            ttl = int(os.environ.get("TB_RECOVERY_PENDING_TTL", "900"))
            con.execute("DELETE FROM iris_recovery_pending WHERE resolved_ts<?",
                        (now - ttl,))
            con.execute("INSERT OR REPLACE INTO iris_recovery_pending(dedup_key,resolved_ts) VALUES(?,?)",
                        (source_ref, now))
            con.commit()
            con.close()
            return False, "pending"
        con.close()
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


def consume_pending_zabbix_recovery(event):
    """Погасить запоздалый PROBLEM, если его RESOLVED уже приходил."""
    if is_zabbix_recovery(event):
        return False
    f = event.get("fields") or {}
    zabbix_event_id = str(f.get("zabbix_event_id") or "").strip()
    if not zabbix_event_id:
        return False
    source_ref = f"zabbix:{zabbix_event_id}"
    with IRIS_LOCK:
        con = state_db()
        now = time.time()
        ttl = int(os.environ.get("TB_RECOVERY_PENDING_TTL", "900"))
        con.execute("DELETE FROM iris_recovery_pending WHERE resolved_ts<?", (now - ttl,))
        row = con.execute("SELECT resolved_ts FROM iris_recovery_pending WHERE dedup_key=?",
                          (source_ref,)).fetchone()
        if row:
            con.execute("DELETE FROM iris_recovery_pending WHERE dedup_key=?", (source_ref,))
        con.commit()
        con.close()
        return bool(row)


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
    con.execute("""CREATE TABLE IF NOT EXISTS iris_recovery_pending(
        dedup_key TEXT PRIMARY KEY, resolved_ts REAL NOT NULL)""")
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
            event_type = {"pending": "iris_recovery_pending",
                          "not_found": "iris_recovery_skip"}.get(info, "iris_recovery_error")
            send_gelf(f"TicketBridge: Zabbix RESOLVED {zabbix_event_id}: {info}",
                      tool="ticketbridge", tb_event=event_type,
                      zabbix_event_id=zabbix_event_id, corr=corr_key(event))
        return None

    if consume_pending_zabbix_recovery(event):
        zabbix_event_id = str((event.get("fields") or {}).get("zabbix_event_id") or "")
        send_gelf(f"TicketBridge: запоздалый Zabbix PROBLEM {zabbix_event_id} подавлен: "
                  "RESOLVED уже получен", tool="ticketbridge", tb_event="iris_race_suppressed",
                  zabbix_event_id=zabbix_event_id, corr=corr_key(event))
        return None

    event = with_maintenance_context(event)
    if maintenance_is_active(event):
        fields = event.get("fields") or {}
        send_gelf("TicketBridge: availability-алерт обогащён окном обслуживания HostDeck",
                  tool="ticketbridge", tb_event="maintenance_context",
                  event_id=str(event.get("id") or ""),
                  event_definition_id=str(event.get("event_definition_id") or ""),
                  corr=corr_key(event),
                  maintenance_until=str(fields.get("maintenance_until") or ""),
                  maintenance_reason=str(fields.get("maintenance_reason") or ""))
    priority = int(event.get("priority") or 2)
    tid = _handle_event(event) if priority == 3 or is_recovery(event) else None
    if not is_recovery(event):
        ok, info = send_iris(event)
        send_gelf(f"TicketBridge: IRIS {'алерт #' + info if ok else 'ОШИБКА: ' + info}",
                  tool="ticketbridge", tb_event="iris_alert" if ok else "iris_error",
                  corr=corr_key(event), ticket_id=tid or 0)
        if ok:
            # Планировщик вызывается после send_iris и вне IRIS_LOCK. По умолчанию
            # off: не создаёт поток, БД или сетевые вызовы и не влияет на ответ /hook.
            auto_triage_hook.maybe_start(event, info, STATE_DB, log=send_gelf)
    return tid


_COLLECTION_JOBS = None


def _case_collection_job(case_id, asset_id, client_id, platform, artifacts, progress):
    return manual_collection.collect_many_and_attach(
        case_id, client_id, platform, artifacts, asset_id=asset_id, progress=progress)


def _alert_collection_job(alert_id, asset_id, client_id, platform, artifacts, progress):
    def collect(case_id, resolved_client_id, resolved_platform, resolved_artifacts, asset_id=None):
        return manual_collection.collect_many_and_attach(
            case_id, resolved_client_id, resolved_platform, resolved_artifacts,
            asset_id=asset_id, progress=progress)

    return alert_collection.collect_from_alert(
        alert_id, asset_id, client_id, platform, artifacts,
        iris_request=_iris_request, escalate=_iris_escalate, collect=collect)


def _collection_job_notification(job):
    if job.get("kind") != "alert":
        return
    result = job.get("result") or {}
    lines = [
        f"### Velociraptor collection `{job['job_id']}`",
        f"- Status: **{job['status']}**",
        f"- Incident: {job.get('case_id') or 'not created'}",
    ]
    if result.get("evidence_id"):
        lines.extend([
            f"- Evidence ID: `{result['evidence_id']}`",
            f"- File: `{result.get('filename') or 'see incident Evidence'}`",
            f"- SHA-256: `{result.get('sha256') or 'unknown'}`",
        ])
    for flow in result.get("artifacts") or []:
        lines.append(f"- [{flow.get('artifact')} / {flow.get('flow_id')}]({flow.get('flow_link')})")
    if job.get("error"):
        lines.append(f"- Error: {job['error']}")
    _iris_add_comment(job["target_id"], "\n".join(lines))


def _evidence_retry_job(job, package_path):
    """Reuse the private spool; no Velociraptor collector is available here."""
    return manual_collection.attach_existing_pack(
        job["case_id"], package_path.read_bytes(), job["result"])


def _collection_job_manager():
    global _COLLECTION_JOBS
    if _COLLECTION_JOBS is None:
        _COLLECTION_JOBS = collection_jobs.CollectionJobManager(
            STATE_DB, case_runner=_case_collection_job,
            alert_runner=_alert_collection_job,
            evidence_retry_runner=_evidence_retry_job,
            notify=_collection_job_notification,
            max_parallel=int(os.environ.get("TB_VR_MANUAL_MAX_PARALLEL", "2")))
    return _COLLECTION_JOBS


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_OPTIONS(self):
        p = urlparse(self.path)
        jobs_path = p.path == "/velociraptor/jobs" or p.path.startswith("/velociraptor/jobs/")
        if p.path not in ("/velociraptor/collect", "/velociraptor/alert-collect",
                          "/velociraptor/catalog", "/velociraptor/resolve-client") and not jobs_path:
            return self._json({"error": "not found"}, 404)
        if parse_qs(p.query).get("key", [""])[0] != KEY:
            return self._json({"error": "bad key"}, 403)
        self.send_response(204)
        self._cors_headers()
        methods = ("GET, OPTIONS" if (p.path in
                   ("/velociraptor/catalog", "/velociraptor/resolve-client")
                   or (jobs_path and not p.path.endswith("/retry-evidence")))
                   else "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Methods", methods)
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        p = urlparse(self.path)
        retry_match = re.fullmatch(r"/velociraptor/jobs/([^/]+)/retry-evidence", p.path)
        if p.path not in ("/hook", "/velociraptor/collect",
                          "/velociraptor/alert-collect") and not retry_match:
            return self._json({"error": "not found"}, 404)
        if parse_qs(p.query).get("key", [""])[0] != KEY:
            return self._json({"error": "bad key"}, 403)
        n = int(self.headers.get("Content-Length", 0))
        if n > MAX_BODY_BYTES:
            return self._json({"error": "request too large"}, 413)
        if retry_match:
            try:
                job_id = retry_match.group(1)
                if not re.fullmatch(r"[0-9a-f]{32}", job_id):
                    raise ValueError("Invalid job_id")
                form = parse_qs(self.rfile.read(n).decode("utf-8"), keep_blank_values=True)
                if set(form) != {"confirm"} or form.get("confirm") != ["yes"]:
                    raise ValueError("Only explicit confirmation is accepted")
                job = _collection_job_manager().retry_evidence(job_id)
                return self._json({"ok": True, "job": job})
            except KeyError:
                return self._json({"ok": False, "error": "Collection job not found"}, 404)
            except (collection_jobs.CollectionJobRecoveryError,
                    collection_jobs.CollectionJobBusy) as error:
                return self._json({"ok": False, "error": str(error)}, 409)
            except (ValueError, TypeError) as error:
                return self._json({"ok": False, "error": str(error)}, 400)
            except Exception as error:
                return self._json({"ok": False, "error": str(error)[:800]}, 502)
        if p.path == "/velociraptor/alert-collect":
            try:
                form = parse_qs(self.rfile.read(n).decode("utf-8"), keep_blank_values=True)
                allowed_fields = {"alert_id", "asset_id", "client_id", "confirm",
                                  "response", "platform", "artifacts", "async"}
                if set(form) - allowed_fields:
                    raise ValueError("Only reviewed alert collection fields are accepted")
                alert_id = int(form.get("alert_id", ["0"])[0])
                asset_id = int(form.get("asset_id", ["0"])[0])
                client_id = form.get("client_id", [""])[0].strip()
                platform = form.get("platform", [""])[0]
                artifacts = form.get("artifacts") or []
                if form.get("async", ["0"]) not in (["0"], ["1"]):
                    raise ValueError("Invalid async flag")
                if (alert_id <= 0 or asset_id <= 0
                        or form.get("confirm") != ["yes"]):
                    raise ValueError("alert_id, asset_id and explicit confirmation are required")
                velociraptor_evidence.VelociraptorCollector.validate_client_id(client_id)
                manual_collection.validate_selection(platform, artifacts)
                if form.get("async") == ["1"]:
                    job, duplicate = _collection_job_manager().start_alert(
                        alert_id, asset_id, client_id, platform, artifacts)
                    return self._json({"ok": True, "job": job, "duplicate": duplicate},
                                      200 if duplicate else 202)
                result = alert_collection.collect_from_alert(
                    alert_id, asset_id, client_id, platform, artifacts,
                    iris_request=_iris_request, escalate=_iris_escalate,
                    collect=manual_collection.collect_many_and_attach)
            except collection_jobs.CollectionJobBusy as error:
                return self._json({"ok": False, "error": str(error)}, 429)
            except alert_collection.AlertCollectionError as error:
                payload = {"ok": False, "error": str(error),
                           "alert_id": error.alert_id}
                if error.case_id is not None:
                    payload.update(case_id=error.case_id,
                                   case_created=error.case_created)
                return self._json(payload, error.status)
            except (ValueError, TypeError,
                    velociraptor_evidence.VelociraptorError) as error:
                return self._json({"ok": False, "error": str(error)}, 400)
            except Exception as error:
                return self._json({"ok": False, "error": str(error)[:800]}, 502)
            return self._json({"ok": True, **result})
        if p.path == "/velociraptor/collect":
            as_json = False
            multi = False
            try:
                form = parse_qs(self.rfile.read(n).decode("utf-8"), keep_blank_values=True)
                as_json = form.get("response") == ["json"]
                multi = "artifacts" in form or "platform" in form
                case_id = int(form.get("case_id", ["0"])[0])
                client_id = form.get("client_id", [""])[0].strip()
                raw_asset_id = form.get("asset_id", [""])[0].strip()
                asset_id = int(raw_asset_id) if raw_asset_id else None
                if (case_id <= 0 or (asset_id is not None and asset_id <= 0)
                        or form.get("confirm") != ["yes"]):
                    raise ValueError("case_id, valid asset_id and explicit confirmation are required")
                if multi:
                    allowed_fields = {"case_id", "asset_id", "client_id", "confirm",
                                      "response", "platform", "artifacts", "async"}
                    if set(form) - allowed_fields or "artifact" in form:
                        raise ValueError("Only platform and artifacts[] are accepted; VQL and parameters are forbidden")
                    if form.get("async", ["0"]) not in (["0"], ["1"]):
                        raise ValueError("Invalid async flag")
                    platform = form.get("platform", [""])[0]
                    artifacts = form.get("artifacts") or []
                    manual_collection.validate_selection(platform, artifacts)
                    if form.get("async") == ["1"]:
                        if asset_id is None:
                            raise ValueError("asset_id is required for background collection")
                        job, duplicate = _collection_job_manager().start_case(
                            case_id, asset_id, client_id, platform, artifacts)
                        return self._json({"ok": True, "job": job, "duplicate": duplicate},
                                          200 if duplicate else 202)
                    result = manual_collection.collect_many_and_attach(
                        case_id, client_id, platform, artifacts, asset_id=asset_id)
                else:
                    artifact = form.get(
                        "artifact", [velociraptor_evidence.DEFAULT_ARTIFACT])[0]
                    try:
                        artifact = velociraptor_evidence.validate_artifact(artifact)
                    except velociraptor_evidence.VelociraptorError as error:
                        raise ValueError(str(error)) from error
                    result = velociraptor_evidence.collect_and_attach(
                        case_id, client_id, asset_id=asset_id, artifact=artifact)
            except collection_jobs.CollectionJobBusy as error:
                return self._json({"ok": False, "error": str(error)}, 429)
            except (ValueError, TypeError) as error:
                if as_json:
                    return self._json({"ok": False, "error": str(error)}, 400)
                return self._html("Ошибка запроса", f"<p>{esc(error)}</p>", 400)
            except Exception as error:
                if as_json:
                    return self._json({"ok": False, "error": str(error)[:800]}, 502)
                return self._html("Сбор не выполнен",
                                  f"<p>{esc(str(error)[:800])}</p>", 502)
            if as_json:
                return self._json({"ok": True, **result})
            if multi:
                flow_items = "".join(
                    f"<li><a href='{esc(item['flow_link'])}'>{esc(item['artifact'])} — "
                    f"{esc(item['flow_id'])}</a></li>" for item in result["artifacts"])
                body = (f"<p>Мультисбор завершён со статусом <b>{esc(result['status'])}</b>; "
                        "ZIP загружен в Evidence кейса.</p>"
                        f"<dl><dt>Успешных сборов</dt><dd>{len(result['artifacts'])}</dd>"
                        f"<dt>Ошибок</dt><dd>{len(result['errors'])}</dd>"
                        f"<dt>Evidence ID</dt><dd>{result['evidence_id']}</dd>"
                        f"<dt>SHA-256</dt><dd><code>{result['sha256']}</code></dd></dl>"
                        f"<ul>{flow_items}</ul>"
                        f"<p><a href='{esc(IRIS)}/case/{case_id}/evidence'>Открыть Evidence кейса</a></p>")
            else:
                body = (f"<p>Сбор завершён, ZIP загружен в Evidence кейса.</p>"
                        f"<dl><dt>Flow</dt><dd>{esc(result['flow_id'])}</dd>"
                        f"<dt>Evidence ID</dt><dd>{result['evidence_id']}</dd>"
                        f"<dt>SHA-256</dt><dd><code>{result['sha256']}</code></dd></dl>"
                        f"<p><a href='{esc(result['flow_link'])}'>Открыть поток Velociraptor</a> · "
                        f"<a href='{esc(IRIS)}/case/{case_id}/evidence'>Открыть Evidence кейса</a></p>")
            return self._html("Результат Velociraptor", body)
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
        if p.path == "/velociraptor/jobs" or p.path.startswith("/velociraptor/jobs/"):
            query = parse_qs(p.query)
            if query.get("key", [""])[0] != KEY:
                return self._json({"error": "bad key"}, 403)
            manager = _collection_job_manager()
            if p.path == "/velociraptor/jobs":
                if set(query) - {"key", "alert_id", "case_id", "incident_id"}:
                    return self._json({"ok": False, "error": "Invalid job query"}, 400)
                selectors = [name for name in ("alert_id", "case_id", "incident_id")
                             if name in query]
                if len(selectors) != 1:
                    return self._json(
                        {"ok": False, "error": "Specify alert_id, case_id or incident_id"}, 400)
                try:
                    target_id = int(query[selectors[0]][0])
                    if target_id <= 0:
                        raise ValueError
                except (ValueError, TypeError):
                    return self._json({"ok": False, "error": "Invalid job target"}, 400)
                if selectors[0] == "incident_id":
                    return self._json(
                        {"ok": True, "jobs": manager.store.for_case(target_id)})
                kind = "alert" if selectors[0] == "alert_id" else "case"
                return self._json({"ok": True, "job": manager.store.latest(kind, target_id)})
            job_id = p.path.removeprefix("/velociraptor/jobs/")
            if not re.fullmatch(r"[0-9a-f]{32}", job_id):
                return self._json({"ok": False, "error": "Invalid job_id"}, 400)
            job = manager.store.get(job_id)
            if not job:
                return self._json({"ok": False, "error": "Collection job not found"}, 404)
            return self._json({"ok": True, "job": job})
        if p.path == "/velociraptor/resolve-client":
            query = parse_qs(p.query)
            if query.get("key", [""])[0] != KEY:
                return self._json({"error": "bad key"}, 403)
            try:
                if set(query) - {"key", "hostname"}:
                    raise ValueError("Only hostname is accepted")
                result = manual_collection.resolve_client_by_hostname(
                    query.get("hostname", [""])[0])
            except ValueError as error:
                code = getattr(error, "code", "invalid_hostname")
                status = {"client_not_found": 404, "client_ambiguous": 409}.get(code, 400)
                return self._json({"ok": False, "error": str(error), "code": code}, status)
            except Exception as error:
                return self._json({"ok": False, "error": str(error)[:800],
                                   "code": "resolver_error"}, 502)
            return self._json({"ok": True, **result})
        if p.path == "/velociraptor/catalog":
            if parse_qs(p.query).get("key", [""])[0] != KEY:
                return self._json({"error": "bad key"}, 403)
            return self._json({"ok": True, **manual_collection.artifact_catalog()})
        if p.path == "/velociraptor/collect":
            query = parse_qs(p.query)
            if query.get("key", [""])[0] != KEY:
                return self._json({"error": "bad key"}, 403)
            try:
                case_id = int(query.get("case_id", ["0"])[0])
                if case_id <= 0:
                    raise ValueError
            except ValueError:
                return self._json({"error": "bad case_id"}, 400)
            body = (f"<p>Кейс IRIS №{case_id}. Будет запущен только безопасный артефакт "
                    "<code>Generic.Client.Info</code>; произвольные команды не выполняются.</p>"
                    f"<form method='post' action='{esc(self.path)}'>"
                    f"<input type='hidden' name='case_id' value='{case_id}'>"
                    "<label>Velociraptor Client ID<input name='client_id' required "
                    "pattern='C\\.[0-9a-f]{16}' placeholder='C.0123456789abcdef'></label>"
                    "<label class='confirm'><input type='checkbox' name='confirm' value='yes' required> "
                    "Подтверждаю запуск сбора и загрузку результата в Evidence</label>"
                    "<button type='submit'>Запустить сбор</button></form>"
                    "<p class='muted'>Операция может занять несколько минут. Не закрывайте страницу.</p>")
            return self._html("Сбор Velociraptor → IRIS", body)
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

    def _cors_headers(self):
        origin = self.headers.get("Origin", "").rstrip("/")
        if IRIS and origin == IRIS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def _json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self._cors_headers()
        self.end_headers()
        self.wfile.write(data)

    def _html(self, title, body, code=200):
        page = ("<!doctype html><html lang='ru'><meta charset='utf-8'>"
                "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                f"<title>{esc(title)}</title>"
                "<style>body{font:16px system-ui;max-width:760px;"
                "margin:40px auto;padding:0 20px;background:#10141d;color:#e8edf5}"
                "label{display:block;margin:20px 0}input[name=client_id]{display:block;width:100%;"
                "padding:12px;margin-top:8px;font:16px monospace}button{padding:12px 18px;"
                "background:#68a6ff;border:0;border-radius:6px;font-weight:700}a{color:#8bb8ff}"
                ".confirm input{margin-right:8px}.muted{color:#aab4c5}code{overflow-wrap:anywhere}"
                "dt{font-weight:700;margin-top:12px}</style>"
                f"<h1>{esc(title)}</h1>{body}</html>").encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(page)


if __name__ == "__main__":
    threading.Thread(target=sweeper, daemon=True).start()
    print(f"TicketBridge: http://0.0.0.0:{PORT}/hook (GLPI: {GLPI}, "
          f"автозакрытие после {CLOSE_AFTER // 3600} ч тишины)")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
