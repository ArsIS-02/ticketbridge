#!/usr/bin/env python3
"""Автоматический ZIP-пакет доказательств для кейса DFIR-IRIS.

Использует только штатные API IRIS и Graylog. Пакет загружается в папку
Evidences кейса через Datastore API и помечается file_is_evidence=true.
"""
import argparse
import base64
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
import re
import ssl
import urllib.parse
import urllib.request
import uuid
import zipfile

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
GRAYLOG_FIELDS = (
    "timestamp,source,message,application_name,container_name,agent_name,host,"
    "event_id,event_type,level,srcip,dstip,source_ip,destination_ip,src_port,"
    "dstport,destination_port,user,acct,username,gl2_remote_ip,process_name,"
    "process_command_line,tags"
)
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n").encode()


def data_list(body):
    data = body.get("data", body) if isinstance(body, dict) else body
    return data if isinstance(data, list) else []


def multipart(fields, filename, content):
    boundary = "----ticketbridge-" + uuid.uuid4().hex
    body = bytearray()
    for name, value in fields.items():
        body.extend(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n".encode())
        body.extend(str(value).encode())
        body.extend(b"\r\n")
    safe_name = filename.replace('"', "")
    body.extend(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file_content\"; filename=\"{safe_name}\"\r\nContent-Type: application/zip\r\n\r\n".encode())
    body.extend(content)
    body.extend(f"\r\n--{boundary}--\r\n".encode())
    return bytes(body), "multipart/form-data; boundary=" + boundary


class EvidencePack:
    def __init__(self, iris_url, iris_key, graylog_url="", graylog_token="",
                 timeout=30, raw_limit=200):
        self.iris = iris_url.rstrip("/")
        self.iris_key = iris_key
        self.graylog = graylog_url.rstrip("/")
        self.graylog_token = graylog_token
        self.timeout = timeout
        self.raw_limit = raw_limit
        self.errors = []

    def api(self, method, path, payload=None, content_type="application/json"):
        data = payload
        if payload is not None and content_type == "application/json":
            data = json.dumps(payload, ensure_ascii=False).encode()
        request = urllib.request.Request(
            self.iris + path, data=data, method=method,
            headers={"Authorization": "Bearer " + self.iris_key,
                     "Content-Type": content_type, "Accept": "application/json"})
        with urllib.request.urlopen(request, context=CTX, timeout=self.timeout) as response:
            raw = response.read()
            return json.loads(raw.decode() or "{}") if raw.strip() else {}

    def optional(self, label, path):
        try:
            return self.api("GET", path)
        except Exception as error:
            self.errors.append({"source": label, "error": str(error)[:500]})
            return {}

    def graylog_search(self, query, start, end, streams):
        if not (self.graylog and self.graylog_token and query and start and end):
            return []
        params = {"query": query, "from": start, "to": end,
                  "limit": str(self.raw_limit), "fields": GRAYLOG_FIELDS}
        if streams:
            params["filter"] = "streams:" + ",".join(streams)
        url = self.graylog + "/api/search/universal/absolute?" + urllib.parse.urlencode(params)
        auth = base64.b64encode((self.graylog_token + ":token").encode()).decode()
        request = urllib.request.Request(url, headers={
            "Authorization": "Basic " + auth, "X-Requested-By": "ticketbridge-evidence"})
        with urllib.request.urlopen(request, context=CTX, timeout=self.timeout) as response:
            raw = response.read().decode("utf-8", "replace")
        try:
            body = json.loads(raw)
            return [item.get("message", item) for item in body.get("messages", [])]
        except json.JSONDecodeError:
            return list(csv.DictReader(io.StringIO(raw)))

    @staticmethod
    def source_content(alert, fallback):
        content = alert.get("alert_source_content") if alert else None
        if isinstance(content, str):
            try:
                content = json.loads(content)
            except json.JSONDecodeError:
                content = None
        return content if isinstance(content, dict) and content else (fallback or {})

    def build(self, case_id, alert_id=None, trigger_event=None, score=None, hits=None):
        case = self.api("GET", f"/api/v2/cases/{case_id}")
        case = case.get("data", case)
        alerts_body = self.api("GET", f"/api/v2/alerts?case_id={case_id}&per_page=200")
        alerts = data_list(alerts_body)
        primary = next((a for a in alerts if a.get("alert_id") == alert_id), None)
        if primary is None and alert_id:
            primary = self.api("GET", f"/api/v2/alerts/{alert_id}")
            primary = primary.get("data", primary)
            if primary:
                alerts.append(primary)
        if primary is None and alerts:
            primary = alerts[0]
        primary = primary or {}
        source_event = self.source_content(primary, trigger_event)
        replay = source_event.get("replay_info") or {}
        comments = {}
        for alert in alerts:
            identifier = alert.get("alert_id")
            if identifier is not None:
                comments[str(identifier)] = self.optional(
                    f"alert-{identifier}-comments", f"/api/v2/alerts/{identifier}/comments")

        case_assets = data_list(self.optional("case-assets", f"/api/v2/cases/{case_id}/assets?per_page=200"))
        case_iocs = data_list(self.optional("case-iocs", f"/api/v2/cases/{case_id}/iocs?per_page=200"))
        events = self.optional("case-events", f"/api/v2/cases/{case_id}/events?per_page=200")
        notes = self.optional("case-notes", f"/api/v2/cases/{case_id}/notes")
        previous_evidences = self.optional("case-evidences", f"/api/v2/cases/{case_id}/evidences?per_page=200")
        raw_events, context_events = [], []
        if replay:
            try:
                raw_events = self.graylog_search(replay.get("query"), replay.get("timerange_start"),
                                                 replay.get("timerange_end"), replay.get("streams") or [])
            except Exception as error:
                self.errors.append({"source": "graylog-original", "error": str(error)[:500]})
            names = [a.get("asset_name") for a in primary.get("assets") or []
                     if a.get("asset_name") and a.get("asset_type_id") not in (1, 5, 18)]
            if names:
                name = str(names[0]).replace('"', "")
                query = f'(source:"{name}" OR agent_name:"{name}" OR host:"{name}")'
                try:
                    # Контекст ищем по всем стримам: Wazuh/osquery/Sysmon могут
                    # не входить в стрим исходного правила.
                    context_events = self.graylog_search(query, replay.get("timerange_start"),
                                                         replay.get("timerange_end"), [])
                except Exception as error:
                    self.errors.append({"source": "graylog-context", "error": str(error)[:500]})

        links = {"graylog_replay": primary.get("alert_source_link"), "trafficlens": []}
        for value in (source_event, trigger_event or {}):
            for url in URL_RE.findall(json.dumps(value, ensure_ascii=False)):
                if "trafficlens" in url.lower() and url not in links["trafficlens"]:
                    links["trafficlens"].append(url.rstrip("),.;"))
        generated = datetime.now(timezone.utc).isoformat()
        files = {
            "iris/case.json": case,
            "iris/alerts.json": alerts,
            "iris/alert_comments.json": comments,
            "iris/assets.json": {"case": case_assets,
                                 "alerts": {str(a.get("alert_id")): a.get("assets") or [] for a in alerts}},
            "iris/iocs.json": {"case": case_iocs,
                               "alerts": {str(a.get("alert_id")): a.get("iocs") or [] for a in alerts}},
            "iris/timeline.json": events,
            "iris/notes.json": notes,
            "iris/enrichment_history.json": {
                str(a.get("alert_id")): a.get("modification_history") for a in alerts},
            "iris/previous_evidences.json": previous_evidences,
            "graylog/trigger_event.json": trigger_event or source_event,
            "graylog/original_events.json": raw_events,
            "graylog/context_events.json": context_events,
            "graylog/replay.json": replay,
            "links.json": links,
            "collection_errors.json": self.errors,
        }
        metadata = {"case_id": case_id, "alert_id": primary.get("alert_id") or alert_id,
                    "score": score, "hits": hits, "generated_at": generated,
                    "original_event_count": len(raw_events),
                    "context_event_count": len(context_events),
                    "collection_errors": len(self.errors)}
        files["README.md"] = self.render_readme(case, primary, metadata, links)
        encoded = {name: (value if isinstance(value, bytes) else
                          value.encode() if isinstance(value, str) else json_bytes(value))
                   for name, value in files.items()}
        manifest = {"algorithm": "sha256", "generated_at": generated,
                    "files": {name: {"size": len(content),
                                     "sha256": hashlib.sha256(content).hexdigest()}
                              for name, content in sorted(encoded.items())}}
        encoded["manifest.json"] = json_bytes(manifest)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, content in sorted(encoded.items()):
                archive.writestr(name, content)
        content = buffer.getvalue()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        metadata.update(filename=f"case-{case_id}-evidence-{stamp}.zip",
                        size=len(content), sha256=hashlib.sha256(content).hexdigest())
        return content, metadata

    @staticmethod
    def render_readme(case, primary, metadata, links):
        asset_names = [a.get("asset_name") for a in primary.get("assets") or [] if a.get("asset_name")]
        lines = [
            f"# Пакет доказательств: кейс IRIS №{metadata['case_id']}", "",
            f"- Кейс: {case.get('case_name') or '—'}",
            f"- Алерт: №{metadata['alert_id'] or '—'} — {primary.get('alert_title') or '—'}",
            f"- Скор / срабатывания: {metadata['score'] if metadata['score'] is not None else '—'} / {metadata['hits'] or '—'}",
            f"- Сформировано (UTC): {metadata['generated_at']}",
            f"- Активы алерта: {', '.join(asset_names) if asset_names else '—'}",
            f"- Исходных сообщений Graylog: {metadata['original_event_count']}",
            f"- Контекстных сообщений хоста: {metadata['context_event_count']}", "",
            "## Содержимое", "",
            "В `iris/` — снимок кейса, алертов, комментариев, активов, IOC, заметок и временной шкалы.",
            "В `graylog/` — исходное событие, исходные сообщения и контекст хоста за replay-окно.",
            "В `manifest.json` — размер и SHA-256 каждого файла пакета.", "",
            "## Ссылки", "",
            f"- Graylog replay: {links.get('graylog_replay') or '—'}",
            f"- TrafficLens: {', '.join(links.get('trafficlens') or []) or 'не найдено в событии'}", "",
            "Пакет является снимком на момент формирования; последующие изменения кейса в него не входят.",
        ]
        return "\n".join(lines) + "\n"

    def attach(self, case_id, content, metadata):
        tree = self.api("GET", f"/api/v2/cases/{case_id}/datastore/tree")
        tree = tree.get("data", tree)

        def find_folder(nodes, preferred):
            for key, node in nodes.items():
                if node.get("type") == "directory":
                    if preferred and node.get("name", "").lower() == "evidences":
                        return key
                    found = find_folder(node.get("children") or {}, preferred)
                    if found:
                        return found
            return ""

        folder = find_folder(tree, True) or find_folder(tree, False)
        if not folder or not folder.startswith("d-"):
            raise RuntimeError("Datastore folder not found")
        body, content_type = multipart({
            "file_original_name": metadata["filename"],
            "file_description": (f"Автоматический пакет доказательств TicketBridge; "
                                 f"SHA-256 {metadata['sha256']}; снимок {metadata['generated_at']}"),
            "file_is_evidence": "true",
            "file_tags": "ticketbridge,evidence-pack,graylog",
        }, metadata["filename"], content)
        uploaded = self.api("POST", f"/api/v2/cases/{case_id}/datastore/folders/{folder[2:]}/files",
                            payload=body, content_type=content_type)
        uploaded = uploaded.get("data", uploaded)
        file_id = uploaded.get("file_id")
        if not file_id:
            raise RuntimeError("IRIS did not return file_id for evidence pack")
        info = self.api("GET", f"/api/v2/cases/{case_id}/datastore/files/{file_id}/info")
        info = info.get("data", info)
        if info.get("file_sha256", "").lower() != metadata["sha256"]:
            raise RuntimeError("Evidence pack SHA-256 mismatch after upload")
        evidences = data_list(self.api("GET", f"/api/v2/cases/{case_id}/evidences?per_page=200"))
        evidence = next((e for e in evidences if e.get("filename") == metadata["filename"]), None)
        if not evidence:
            raise RuntimeError("Evidence registry entry was not created")
        return {"file_id": file_id, "evidence_id": evidence.get("id"),
                "filename": metadata["filename"], "sha256": metadata["sha256"],
                "size": metadata["size"], "original_events": metadata["original_event_count"],
                "context_events": metadata["context_event_count"],
                "collection_errors": metadata["collection_errors"]}

    def build_and_attach(self, case_id, alert_id=None, trigger_event=None, score=None, hits=None):
        content, metadata = self.build(case_id, alert_id, trigger_event, score, hits)
        return self.attach(case_id, content, metadata)


def build_and_attach(case_id, alert_id, iris_url, iris_key, graylog_url, graylog_token,
                     trigger_event=None, score=None, hits=None):
    pack = EvidencePack(iris_url, iris_key, graylog_url, graylog_token,
                        raw_limit=int(os.environ.get("TB_EVIDENCE_RAW_LIMIT", "200")))
    return pack.build_and_attach(case_id, alert_id, trigger_event, score, hits)


def main():
    parser = argparse.ArgumentParser(description="Сформировать и приложить пакет доказательств к кейсу IRIS")
    parser.add_argument("case_id", type=int)
    parser.add_argument("--alert-id", type=int)
    args = parser.parse_args()
    pack = EvidencePack(os.environ["TB_IRIS_URL"], os.environ["TB_IRIS_KEY"],
                        os.environ.get("TB_GRAYLOG_URL", ""), os.environ.get("TB_GRAYLOG_TOKEN", ""))
    print(json.dumps(pack.build_and_attach(args.case_id, args.alert_id), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
