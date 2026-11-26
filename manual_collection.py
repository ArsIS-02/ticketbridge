#!/usr/bin/env python3
"""Manual multi-artifact Velociraptor collection for the IRIS case dialog.

Artifact names and parameter builders come only from the reviewed playbook
registry and the separately reviewed RED OS set. The browser cannot supply VQL,
artifact parameters or commands. Each artifact gets its own Flow; one verified
Evidence ZIP contains all successful results and per-artifact errors.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
import re
import time
import zipfile

from collection_playbooks import PlaybookRegistry, build_parameters
from iris_evidence_pack import EvidencePack, json_bytes
import velociraptor_evidence as legacy

MAX_ARTIFACTS = 8
MAX_ROW_LIMIT = 10000
MAX_TOTAL_SECONDS = 1800
MANUAL_WINDOW_DAYS = 30
ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.]+$")
PLATFORM_LABELS = {
    "linux": "RED OS / Linux",
    "darwin": "macOS",
    "windows": "Windows",
}
RECOMMENDED = {
    "linux": ["Generic.Client.Info", "Linux.Sys.Pslist", "Linux.Network.NetstatEnriched"],
    "darwin": ["Generic.Client.Info", "Linux.Sys.Pslist", "MacOS.Network.Netstat"],
    "windows": ["Generic.Client.Info", "Windows.System.Pslist",
                "Windows.Network.NetstatEnriched"],
}


class ManualCollectionError(ValueError):
    pass


def _vql_string(value):
    """Encode a value as a single quoted VQL string literal."""
    encoded = json.dumps(str(value), ensure_ascii=True)[1:-1]
    return "'" + encoded.replace("'", "\\'") + "'"


def _build_specs():
    registry = PlaybookRegistry.load()
    specs = {platform: {} for platform in PLATFORM_LABELS}
    for playbook in registry.playbooks.values():
        platform = playbook["platform"]
        for artifact in playbook["artifacts"]:
            name = artifact["name"]
            previous = specs[platform].get(name)
            if previous and previous != artifact["parameter_builder"]:
                raise ManualCollectionError(
                    f"Conflicting parameter builders for {name} on {platform}")
            specs[platform][name] = artifact["parameter_builder"]
    for name in sorted(legacy.REDOS_COMPLIANCE_ARTIFACTS | legacy.REDOS_DETECTION_ARTIFACTS):
        specs["linux"][name] = "empty"
    return specs


ARTIFACT_SPECS = _build_specs()
ALLOWED_ARTIFACTS = frozenset(
    name for artifacts in ARTIFACT_SPECS.values() for name in artifacts)


def _label(name):
    special = {
        "Generic.Client.Info": "Host information",
        "Generic.System.HostsFile": "Hosts file",
        "Linux.Sys.Pslist": "Processes (Linux-compatible)",
    }
    return special.get(name, name.rsplit(".", 1)[-1])


def _description(name):
    if name in legacy.REDOS_DNF_ARTIFACTS:
        return ("Checks security updates through DNF. May contact configured repositories "
                "and refresh metadata; never installs packages.")
    if name == "Custom.REDOS.Detection.SuspiciousXattrs":
        return ("Checks only first-level entries in selected directories; "
                "not a recursive filesystem scan.")
    if name == "Custom.REDOS.Detection.HackingTools":
        return ("Inventories dual-use tools. A match requires a legitimacy review "
                "and is not an incident by itself.")
    if name == "Linux.Sys.Pslist":
        return "Reviewed process listing; also used by the approved macOS process playbook."
    return ("Reviewed collection with server-fixed parameters. "
            "Results require manual analysis; no remediation is performed.")


def artifact_catalog():
    """Return the browser catalog derived from the same server-side allowlist."""
    platforms = []
    for platform, label in PLATFORM_LABELS.items():
        recommended = RECOMMENDED[platform]
        artifacts = [{
            "name": name,
            "label": _label(name),
            "description": _description(name),
            "recommended": name in recommended,
        } for name in sorted(ARTIFACT_SPECS[platform])]
        platforms.append({"id": platform, "label": label, "artifacts": artifacts})
    return {
        "schema_version": 1,
        "max_artifacts": MAX_ARTIFACTS,
        "manual_window_days": MANUAL_WINDOW_DAYS,
        "platforms": platforms,
    }


def validate_selection(platform, artifacts):
    platform = str(platform or "")
    if platform not in ARTIFACT_SPECS:
        raise ManualCollectionError("Unknown or missing collection platform")
    if not isinstance(artifacts, (list, tuple)) or not artifacts:
        raise ManualCollectionError("Select at least one collection artifact")
    if len(artifacts) > MAX_ARTIFACTS:
        raise ManualCollectionError(f"No more than {MAX_ARTIFACTS} artifacts per run")
    selected = []
    for artifact in artifacts:
        if not isinstance(artifact, str) or not ARTIFACT_NAME_RE.fullmatch(artifact):
            raise ManualCollectionError("Invalid Velociraptor artifact name")
        if artifact in selected:
            raise ManualCollectionError("Duplicate artifacts are not allowed")
        if artifact not in ARTIFACT_SPECS[platform]:
            raise ManualCollectionError(
                f"Artifact is not allowed for {PLATFORM_LABELS[platform]}: {artifact}")
        selected.append(artifact)
    return platform, selected


def _window(now):
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)

    def fmt(value):
        return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    return {
        "start": fmt(current - timedelta(days=MANUAL_WINDOW_DAYS)),
        "end": fmt(current + timedelta(minutes=5)),
    }


def _prepared_artifacts(platform, artifacts, window):
    registry = PlaybookRegistry.load()
    schemas = registry.data.get("artifact_schemas") or {}
    prepared = []
    for name in artifacts:
        builder = ARTIFACT_SPECS[platform][name]
        parameters, warnings = build_parameters(builder, {}, window)
        unknown = sorted(set(parameters) - set(schemas.get(name, parameters)))
        if unknown:
            raise ManualCollectionError(
                f"Artifact parameters exceed the installed schema: {name}")
        prepared.append({"name": name, "parameter_builder": builder,
                         "parameters": parameters, "warnings": warnings})
    return prepared


def _flow_for_artifact(collector, client_id, artifact, started_us):
    vql = (
        "SELECT session_id, state, create_time, total_collected_rows "
        f"FROM flows(client_id={_vql_string(client_id)}) "
        f"WHERE create_time >= {started_us} "
        f"AND request.creator={_vql_string(collector.creator)} "
        f"AND {_vql_string(artifact)} IN request.artifacts "
        "ORDER BY create_time DESC LIMIT 1")
    flows = collector.query(vql, timeout=30)
    if not flows:
        raise legacy.VelociraptorError("Collection flow was not found")
    flow = flows[0]
    flow_id = str(flow.get("session_id") or "")
    if not legacy.FLOW_ID_RE.fullmatch(flow_id) or flow.get("state") != "FINISHED":
        raise legacy.VelociraptorError("Collection flow did not finish successfully")
    return flow


def collect_many(collector, client_id, platform, artifacts, now=None):
    """Run approved Flows sequentially; retain partial results and all errors."""
    platform, artifacts = validate_selection(platform, artifacts)
    client_id = collector.validate_client_id(client_id)
    window = _window(now)
    prepared = _prepared_artifacts(platform, artifacts, window)
    clients = collector.query(
        "SELECT client_id, os_info FROM clients() "
        f"WHERE client_id={_vql_string(client_id)} LIMIT 1", timeout=30)
    if not clients or clients[0].get("client_id") != client_id:
        raise legacy.VelociraptorError("Velociraptor client was not found")
    actual_platform = str((clients[0].get("os_info") or {}).get("system") or "").lower()
    if actual_platform != platform:
        raise ManualCollectionError(
            f"Client OS does not match selection: expected {platform}, got "
            f"{actual_platform or 'unknown'}")

    started = now or datetime.now(timezone.utc)
    deadline = time.monotonic() + MAX_TOTAL_SECONDS
    collections, errors = [], []
    for index, artifact in enumerate(prepared):
        name = artifact["name"]
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            for skipped in prepared[index:]:
                errors.append({"artifact": skipped["name"], "exception": "TimeoutError",
                               "error": "Overall manual collection time budget exhausted"})
            break
        started_us = time.time_ns() // 1000
        try:
            parameters = json.dumps(
                artifact["parameters"], ensure_ascii=True, separators=(",", ":"))
            vql = (
                "SELECT * FROM Artifact.Server.Utils.CollectClient("
                f"Client={_vql_string(client_id)}, ArtifactName={_vql_string(name)}, "
                f"Parameters={_vql_string(parameters)}) LIMIT {MAX_ROW_LIMIT}")
            timeout = min(int(getattr(collector, "timeout", 300)), remaining)
            rows = collector.query(vql, timeout=max(1, timeout))
            flow = _flow_for_artifact(collector, client_id, name, started_us)
            collections.append({
                "artifact": name,
                "parameter_builder": artifact["parameter_builder"],
                "parameters": artifact["parameters"],
                "flow_id": flow["session_id"],
                "flow_created_time_us": flow.get("create_time"),
                "state": flow["state"],
                "row_count": len(rows),
                "total_collected_rows": flow.get("total_collected_rows"),
                "flow_link": collector.flow_link(client_id, flow["session_id"]),
                "rows": rows,
            })
        except Exception as error:
            errors.append({"artifact": name, "exception": type(error).__name__,
                           "error": str(error)[:500]})
    status = "completed" if not errors else "partial" if collections else "failed"
    return {
        "status": status,
        "client_id": client_id,
        "platform": platform,
        "requested_artifacts": artifacts,
        "parameter_window": window,
        "started_at": started.isoformat(),
        "artifacts": collections,
        "errors": errors,
    }


def build_multi_pack(case_id, asset_id, result, collector, now=None):
    generated = (now or datetime.now(timezone.utc)).isoformat()
    client_id = result["client_id"]
    platform = result["platform"]
    collections = result["artifacts"]
    errors = result["errors"]
    public_artifacts = [{key: value for key, value in item.items() if key != "rows"}
                        for item in collections]
    identity = json.dumps([generated, client_id, platform, result["requested_artifacts"]],
                          ensure_ascii=True, separators=(",", ":"))
    batch_id = hashlib.sha256(identity.encode()).hexdigest()[:12]
    collection = {
        "case_id": case_id,
        "asset_id": asset_id,
        "client_id": client_id,
        "platform": platform,
        "batch_id": batch_id,
        "status": result["status"],
        "creator": collector.creator,
        "collected_at": generated,
        "started_at": result["started_at"],
        "parameter_window": result["parameter_window"],
        "requested_artifacts": result["requested_artifacts"],
        "artifacts": public_artifacts,
        "errors": errors,
        "result_count": sum(item["row_count"] for item in collections),
        "collection_errors": len(errors),
    }
    readme_lines = [
        f"# Ручной мультисбор Velociraptor: кейс IRIS №{case_id}", "",
        f"- Клиент: `{client_id}`",
        f"- Asset ID в кейсе IRIS: `{asset_id if asset_id is not None else '—'}`",
        f"- Платформа: `{PLATFORM_LABELS[platform]}`",
        f"- Batch ID: `{batch_id}`",
        f"- Статус: `{result['status']}`",
        f"- Успешных сборов: {len(collections)}",
        f"- Ошибок: {len(errors)}",
        f"- Сформировано (UTC): {generated}",
        f"- Временное окно параметров: `{result['parameter_window']['start']}` — "
        f"`{result['parameter_window']['end']}`", "",
        "Каждый артефакт запущен отдельным Flow последовательно. Исходные строки находятся "
        "в `velociraptor/results/`, параметры и Flow ID — в `velociraptor/collection.json`, "
        "ошибки — в `velociraptor/errors.json`, SHA-256 файлов — в `manifest.json`.",
        "Временное окно применяется только к артефактам, параметры которых его требуют. "
        "Произвольные VQL, команды, параметры и remediation не принимаются.", "",
        "## Результаты", "",
    ]
    for item in public_artifacts:
        readme_lines.append(
            f"- `{item['artifact']}` — `{item['state']}`, Flow `{item['flow_id']}`, "
            f"строк: {item['row_count']}, {item['flow_link']}")
    for error in errors:
        readme_lines.append(f"- `{error['artifact']}` — ОШИБКА: {error['error']}")
    files = {
        "README.md": ("\n".join(readme_lines) + "\n").encode(),
        "velociraptor/collection.json": json_bytes(collection),
        "velociraptor/errors.json": json_bytes(errors),
    }
    for item in collections:
        safe_name = item["artifact"].replace(".", "_")
        files[f"velociraptor/results/{safe_name}.json"] = json_bytes(item["rows"])
    manifest = {
        "algorithm": "sha256", "generated_at": generated,
        "files": {name: {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                  for name, content in sorted(files.items())},
    }
    files["manifest.json"] = json_bytes(manifest)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(files.items()):
            archive.writestr(name, content)
    content = buffer.getvalue()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    digest = hashlib.sha256(content).hexdigest()
    metadata = {
        "filename": f"case-{case_id}-velociraptor-{platform}-{stamp}-{batch_id}.zip",
        "generated_at": generated,
        "size": len(content),
        "sha256": digest,
        "original_event_count": collection["result_count"],
        "context_event_count": 0,
        "collection_errors": len(errors),
        "file_tags": f"ticketbridge,evidence-pack,velociraptor,manual-multi,{platform}",
        "file_description": (
            f"Manual Velociraptor {platform} multi-collection; {len(collections)} succeeded, "
            f"{len(errors)} failed; SHA-256 {digest}"),
    }
    return content, metadata, collection


def resolve_client_by_hostname(hostname, environ=None, collector=None):
    """Resolve one Velociraptor client without creating a Flow or changing IRIS.

    Matching is delegated to the same fail-closed hostname/FQDN resolver used by
    automatic triage. The VQL is constant; the hostname is never interpolated.
    """
    from collection_playbooks import normalize_name, resolve_client

    normalized = normalize_name(hostname)
    if not normalized or len(normalized) > 253:
        raise ManualCollectionError("A valid asset hostname is required")
    env = os.environ if environ is None else environ
    collector = collector or legacy.VelociraptorCollector(
        binary=env.get("TB_VR_BINARY", "/opt/velociraptor/velociraptor"),
        api_config=env.get("TB_VR_API_CONFIG", ""),
        gui_url=env.get("TB_VR_GUI_URL", "https://velociraptor.example.test"),
        creator=env.get("TB_VR_CREATOR", "ticketbridge-collector"),
        timeout=int(env.get("TB_VR_TIMEOUT", "300")),
    )
    clients = collector.query(
        "SELECT client_id, last_seen_at, os_info FROM clients()", timeout=30)
    client, evidence = resolve_client(
        [{"value": normalized, "source": "iris.asset_name"}], clients)
    client_id = legacy.VelociraptorCollector.validate_client_id(client.get("client_id"))
    os_info = client.get("os_info") or {}
    system = str(os_info.get("system") or "").lower()
    if system not in PLATFORM_LABELS:
        raise ManualCollectionError("Velociraptor returned an unsupported client OS")
    return {
        "client_id": client_id,
        "hostname": str(os_info.get("hostname") or ""),
        "fqdn": str(os_info.get("fqdn") or ""),
        "platform": system,
        "matched_by": evidence[0]["candidate"]["source"],
    }


class EvidenceDeliveryError(RuntimeError):
    """The Flow finished and the ZIP was built, but IRIS did not accept it."""

    def __init__(self, message, collection_result, package_content=None):
        super().__init__(message)
        self.collection_result = collection_result
        # Bytes stay in process memory just long enough for CollectionJobManager
        # to persist them in its private recovery spool; they are not put in JSON.
        self.package_content = package_content


def _delivery_metadata(result):
    errors = result.get("errors") or []
    result_count = int(result.get("result_count") or 0)
    return {
        "filename": result["filename"],
        "generated_at": result.get("collected_at") or result.get("generated_at"),
        "size": int(result["size"]),
        "sha256": result["sha256"],
        "original_event_count": result_count,
        "context_event_count": 0,
        "collection_errors": len(errors),
        "file_tags": (
            f"ticketbridge,evidence-pack,velociraptor,manual-multi,{result['platform']}"),
        "file_description": (
            f"Manual Velociraptor {result['platform']} multi-collection; "
            f"{len(result.get('artifacts') or [])} succeeded, {len(errors)} failed; "
            f"SHA-256 {result['sha256']}"),
    }


def attach_existing_pack(case_id, content, result, environ=None, pack=None):
    """Attach an already collected ZIP without starting another Velociraptor Flow."""
    metadata = _delivery_metadata(result)
    if len(content) != metadata["size"]:
        raise EvidenceDeliveryError("Recovery ZIP size does not match its metadata", result)
    if hashlib.sha256(content).hexdigest() != metadata["sha256"]:
        raise EvidenceDeliveryError("Recovery ZIP SHA-256 does not match its metadata", result)
    env = os.environ if environ is None else environ
    pack = pack or EvidencePack(env.get("TB_IRIS_URL", ""), env.get("TB_IRIS_KEY", ""))
    try:
        attached = pack.attach(case_id, content, metadata)
    except Exception as error:
        raise EvidenceDeliveryError(
            f"Evidence upload retry failed: {str(error)[:500]}", result) from error
    merged = dict(result)
    merged.update(attached)
    return merged


def collect_many_and_attach(case_id, client_id, platform, artifacts, environ=None,
                            pack=None, collector=None, asset_id=None, now=None,
                            progress=None):
    env = os.environ if environ is None else environ
    collector = collector or legacy.VelociraptorCollector(
        binary=env.get("TB_VR_BINARY", "/opt/velociraptor/velociraptor"),
        api_config=env.get("TB_VR_API_CONFIG", ""),
        gui_url=env.get("TB_VR_GUI_URL", "https://velociraptor.example.test"),
        creator=env.get("TB_VR_CREATOR", "ticketbridge-collector"),
        timeout=int(env.get("TB_VR_TIMEOUT", "300")),
    )
    result = collect_many(collector, client_id, platform, artifacts, now=now)
    content, metadata, collection = build_multi_pack(
        case_id, asset_id, result, collector, now=now)
    if progress:
        progress("uploading")
    pack = pack or EvidencePack(env.get("TB_IRIS_URL", ""), env.get("TB_IRIS_KEY", ""))
    try:
        attached = pack.attach(case_id, content, metadata)
    except Exception as error:
        delivery_result = dict(collection)
        delivery_result.update({
            "case_id": case_id,
            "filename": metadata["filename"],
            "size": metadata["size"],
            "sha256": metadata["sha256"],
            "evidence_id": None,
        })
        raise EvidenceDeliveryError(
            f"Velociraptor ZIP was built, but Evidence upload failed: {str(error)[:500]}",
            delivery_result, package_content=content) from error
    attached.update(collection)
    return attached
