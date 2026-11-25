#!/usr/bin/env python3
"""Ручной сбор разрешённых артефактов и передача результата в Evidence IRIS.

Произвольный VQL не принимается, а имена артефактов ограничены ALLOWED_ARTIFACTS.
Все вызовы идут через штатный Velociraptor CLI и API-файл с правами 0600.
"""
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile

from iris_evidence_pack import EvidencePack, json_bytes

DEFAULT_ARTIFACT = "Generic.Client.Info"
REDOS_COMPLIANCE_ARTIFACTS = frozenset({
    "Custom.REDOS.Compliance.AIDE",
    "Custom.REDOS.Compliance.AccountLockout",
    "Custom.REDOS.Compliance.AuditConfiguration",
    "Custom.REDOS.Compliance.AuditLogRotation",
    "Custom.REDOS.Compliance.AuditRules",
    "Custom.REDOS.Compliance.AuditdConfig",
    "Custom.REDOS.Compliance.CriticalFilePermissions",
    "Custom.REDOS.Compliance.CronPermissions",
    "Custom.REDOS.Compliance.CryptoPolicies",
    "Custom.REDOS.Compliance.DisableModuleLoading",
    "Custom.REDOS.Compliance.EmptyPasswords",
    "Custom.REDOS.Compliance.FIPS",
    "Custom.REDOS.Compliance.KernelHardening",
    "Custom.REDOS.Compliance.OpenPorts",
    "Custom.REDOS.Compliance.OpenSCAP",
    "Custom.REDOS.Compliance.PasswordHistory",
    "Custom.REDOS.Compliance.PasswordPolicy",
    "Custom.REDOS.Compliance.SELinuxModules",
    "Custom.REDOS.Compliance.SELinuxStatus",
    "Custom.REDOS.Compliance.SSHHardening",
    "Custom.REDOS.Compliance.SecurityUpdates",
    "Custom.REDOS.Compliance.SecurityUpdatesDetailed",
    "Custom.REDOS.Compliance.SessionTimeout",
    "Custom.REDOS.Compliance.ShadowPermissions",
    "Custom.REDOS.Compliance.StickyBit",
    "Custom.REDOS.Compliance.SuAccess",
    "Custom.REDOS.Compliance.SuidBinaries",
    "Custom.REDOS.Compliance.SyslogConfiguration",
    "Custom.REDOS.Compliance.TimeSync",
})
REDOS_DETECTION_ARTIFACTS = frozenset({
    "Custom.REDOS.Detection.HackingTools",
    "Custom.REDOS.Detection.SuspiciousBindMounts",
    "Custom.REDOS.Detection.SuspiciousXattrs",
})
REDOS_DNF_ARTIFACTS = frozenset({
    "Custom.REDOS.Compliance.SecurityUpdates",
    "Custom.REDOS.Compliance.SecurityUpdatesDetailed",
})
ALLOWED_ARTIFACTS = frozenset(
    {DEFAULT_ARTIFACT} | REDOS_COMPLIANCE_ARTIFACTS | REDOS_DETECTION_ARTIFACTS)
# Сохранено для совместимости с внешними диагностическими скриптами.
ARTIFACT = DEFAULT_ARTIFACT
CLIENT_ID_RE = re.compile(r"^C\.[0-9a-f]{16}$")
FLOW_ID_RE = re.compile(r"^F\.[A-Z0-9]+$")


class VelociraptorError(RuntimeError):
    pass


def validate_artifact(artifact):
    artifact = str(artifact or "")
    if artifact not in ALLOWED_ARTIFACTS:
        raise VelociraptorError("Velociraptor artifact is not allowed")
    return artifact


class VelociraptorCollector:
    def __init__(self, binary, api_config, gui_url, creator, timeout=300,
                 runner=subprocess.run):
        self.binary = binary
        self.api_config = str(api_config)
        self.gui_url = gui_url.rstrip("/")
        self.creator = creator
        self.timeout = int(timeout)
        self.runner = runner

    def query(self, vql, timeout=None):
        mode = Path(self.api_config).stat().st_mode & 0o777
        if mode & 0o077:
            raise VelociraptorError("Velociraptor API config must have mode 0600")
        wait = int(timeout or self.timeout)
        command = [self.binary, "--api_config", self.api_config,
                   "query", "--max_wait", str(wait), "--format", "json", vql]
        try:
            completed = self.runner(command, capture_output=True, text=True,
                                    timeout=wait + 15, check=False)
        except subprocess.TimeoutExpired as error:
            raise VelociraptorError(f"Velociraptor query timed out after {wait}s") from error
        if completed.returncode:
            detail = (completed.stderr or completed.stdout or "unknown API error").strip()
            raise VelociraptorError("Velociraptor API: " + detail[-800:])
        try:
            result = json.loads(completed.stdout or "[]")
        except json.JSONDecodeError as error:
            raise VelociraptorError("Velociraptor returned invalid JSON") from error
        if not isinstance(result, list):
            raise VelociraptorError("Velociraptor returned an unexpected result")
        return result

    @staticmethod
    def validate_client_id(client_id):
        if not CLIENT_ID_RE.fullmatch(str(client_id or "")):
            raise VelociraptorError("Invalid Velociraptor client_id")
        return str(client_id)

    def collect(self, client_id, artifact=DEFAULT_ARTIFACT):
        client_id = self.validate_client_id(client_id)
        artifact = validate_artifact(artifact)
        clients = self.query(
            f"SELECT client_id, os_info FROM clients() WHERE client_id='{client_id}' LIMIT 1",
            timeout=30)
        if not clients or clients[0].get("client_id") != client_id:
            raise VelociraptorError("Velociraptor client was not found")

        # CollectClient выполняет schedule → wait → source. Параметры фиксированы;
        # имя артефакта уже проверено по allowlist и экранируется как VQL-строка.
        artifact_literal = json.dumps(artifact)
        collection_vql = (
            "SELECT * FROM Artifact.Server.Utils.CollectClient("
            f"Client='{client_id}', ArtifactName={artifact_literal}, Parameters='{{}}')")
        rows = self.query(collection_vql)
        if not rows:
            raise VelociraptorError("Collection completed without result rows")

        flow_vql = (
            "SELECT session_id, state, create_time, total_collected_rows "
            f"FROM flows(client_id='{client_id}') "
            f"WHERE {artifact_literal} IN request.artifacts "
            f"AND request.creator='{self.creator}' "
            "ORDER BY create_time DESC LIMIT 1")
        flows = self.query(flow_vql, timeout=30)
        if not flows:
            raise VelociraptorError("Collection flow was not found")
        flow = flows[0]
        flow_id = str(flow.get("session_id") or "")
        if not FLOW_ID_RE.fullmatch(flow_id) or flow.get("state") != "FINISHED":
            raise VelociraptorError("Collection flow did not finish successfully")
        return rows, flow

    def flow_link(self, client_id, flow_id):
        return (f"{self.gui_url}/app/index.html?org_id=root#/collected/"
                f"{client_id}/{flow_id}")

    def build_pack(self, case_id, client_id, rows, flow, asset_id=None,
                   artifact=DEFAULT_ARTIFACT):
        artifact = validate_artifact(artifact)
        generated = datetime.now(timezone.utc).isoformat()
        flow_id = flow["session_id"]
        collection = {
            "case_id": case_id,
            "asset_id": asset_id,
            "client_id": client_id,
            "artifact": artifact,
            "flow_id": flow_id,
            "state": flow["state"],
            "creator": self.creator,
            "flow_created_time_us": flow.get("create_time"),
            "collected_at": generated,
            "result_count": len(rows),
            "flow_link": self.flow_link(client_id, flow_id),
        }
        asset_line = f"- Asset ID в кейсе IRIS: `{asset_id}`\n" if asset_id is not None else ""
        readme = (
            f"# Velociraptor: кейс IRIS №{case_id}\n\n"
            f"- Клиент: `{client_id}`\n"
            f"{asset_line}"
            f"- Артефакт: `{artifact}`\n"
            f"- Flow: `{flow_id}` ({flow['state']})\n"
            f"- Строк результата: {len(rows)}\n"
            f"- Сформировано (UTC): {generated}\n"
            f"- Ссылка: {collection['flow_link']}\n\n"
            "Сбор запущен оператором вручную. В `velociraptor/results.json` "
            "сохранены исходные строки результата, в `manifest.json` — SHA-256 файлов.\n")
        files = {
            "README.md": readme.encode(),
            "velociraptor/collection.json": json_bytes(collection),
            "velociraptor/results.json": json_bytes(rows),
        }
        manifest = {"algorithm": "sha256", "generated_at": generated,
                    "files": {name: {"size": len(content),
                                     "sha256": hashlib.sha256(content).hexdigest()}
                              for name, content in sorted(files.items())}}
        files["manifest.json"] = json_bytes(manifest)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, content in sorted(files.items()):
                archive.writestr(name, content)
        content = buffer.getvalue()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        artifact_tag = artifact.lower().replace(".", "-")
        metadata = {
            "filename": f"case-{case_id}-velociraptor-{flow_id}-{stamp}.zip",
            "generated_at": generated,
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "original_event_count": len(rows),
            "context_event_count": 0,
            "collection_errors": 0,
            "file_tags": f"ticketbridge,evidence-pack,velociraptor,{artifact_tag}",
            "file_description": (f"Velociraptor {artifact}; flow {flow_id}; "
                                 f"SHA-256 {hashlib.sha256(content).hexdigest()}"),
        }
        return content, metadata, collection


def collect_and_attach(case_id, client_id, environ=None, pack=None, collector=None,
                       asset_id=None, artifact=DEFAULT_ARTIFACT):
    artifact = validate_artifact(artifact)
    env = os.environ if environ is None else environ
    collector = collector or VelociraptorCollector(
        binary=env.get("TB_VR_BINARY", "/opt/velociraptor/velociraptor"),
        api_config=env.get("TB_VR_API_CONFIG", ""),
        gui_url=env.get("TB_VR_GUI_URL", "https://velociraptor.example.test"),
        creator=env.get("TB_VR_CREATOR", "ticketbridge-collector"),
        timeout=int(env.get("TB_VR_TIMEOUT", "300")),
    )
    rows, flow = collector.collect(client_id, artifact=artifact)
    content, metadata, collection = collector.build_pack(
        case_id, client_id, rows, flow, asset_id=asset_id, artifact=artifact)
    pack = pack or EvidencePack(env.get("TB_IRIS_URL", ""), env.get("TB_IRIS_KEY", ""))
    attached = pack.attach(case_id, content, metadata)
    attached.update(collection)
    return attached
