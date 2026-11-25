#!/usr/bin/env python3
"""Explicitly confirmed execution of an eligible auto-triage dry-run plan.

The manual CLI and auto_triage_hook call this module only after policy checks.
Every manual execution requires an exact event_id confirmation and an explicit
IRIS case ID. Artifact names and parameters come only from the approved plan.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import time
import zipfile

from collection_playbooks import PlaybookRegistry
from iris_evidence_pack import json_bytes
from velociraptor_evidence import FLOW_ID_RE

ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.]+$")
MAX_TIMEOUT_SECONDS = 600
MAX_ROW_LIMIT = 10000


class AutoTriageExecutionError(ValueError):
    pass


def _vql_string(value):
    """Encode a JSON-compatible value as a single quoted VQL string literal."""
    encoded = json.dumps(str(value), ensure_ascii=True)[1:-1]
    return "'" + encoded.replace("'", "\\'") + "'"


def _require_confirmation(plan, case_id, confirm_event_id):
    if not isinstance(case_id, int) or isinstance(case_id, bool) or case_id <= 0:
        raise AutoTriageExecutionError("A positive explicit IRIS case_id is required")
    auto = plan.get("auto_triage") or {}
    if plan.get("status") != "dry_run" or auto.get("eligible") is not True:
        raise AutoTriageExecutionError("Only an eligible dry-run plan can be confirmed")
    if auto.get("mode") not in {"dry_run", "on"} or auto.get("opted_in") is not True:
        raise AutoTriageExecutionError("The plan is not explicitly opted in")
    if auto.get("kill_switch") is not False:
        raise AutoTriageExecutionError("The kill switch is active")
    expected_event_id = str((plan.get("rule") or {}).get("event_id") or "")
    if not expected_event_id or str(confirm_event_id or "") != expected_event_id:
        raise AutoTriageExecutionError("Exact event_id confirmation is required")
    if plan.get("execution") != {
            "authorized": False, "requires_confirmation": True, "flow_created": False}:
        raise AutoTriageExecutionError("The non-executable plan safety block was changed")


def _approved_artifacts(plan, registry):
    rule_id = str((plan.get("rule") or {}).get("event_definition_id") or "")
    playbook_id, playbook, _ = registry.select(rule_id)
    if (plan.get("playbook") or {}).get("id") != playbook_id:
        raise AutoTriageExecutionError("Playbook identity does not match the registry")
    expected = [item["name"] for item in playbook["artifacts"]]
    artifacts = plan.get("artifacts") or []
    actual = [item.get("name") for item in artifacts]
    if actual != expected:
        raise AutoTriageExecutionError("Artifact list does not match the approved playbook")
    for artifact in artifacts:
        if not ARTIFACT_NAME_RE.fullmatch(artifact["name"]):
            raise AutoTriageExecutionError("Invalid approved artifact name")
        if artifact.get("upload") is not False or not isinstance(artifact.get("parameters"), dict):
            raise AutoTriageExecutionError("Unsafe artifact parameters or upload flag")
    try:
        timeout = int((plan.get("playbook") or {}).get("timeout_seconds", 300))
        row_limit = int((plan.get("playbook") or {}).get("row_limit", MAX_ROW_LIMIT))
    except (TypeError, ValueError) as error:
        raise AutoTriageExecutionError("Invalid playbook limits") from error
    if not 1 <= timeout <= MAX_TIMEOUT_SECONDS or not 1 <= row_limit <= MAX_ROW_LIMIT:
        raise AutoTriageExecutionError("Playbook limits exceed the pilot boundary")
    return artifacts, timeout, row_limit


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
        raise RuntimeError("Collection flow was not found")
    flow = flows[0]
    flow_id = str(flow.get("session_id") or "")
    if not FLOW_ID_RE.fullmatch(flow_id) or flow.get("state") != "FINISHED":
        raise RuntimeError("Collection flow did not finish successfully")
    return flow


def _zip_evidence(plan, case_id, collections, errors, generated):
    files = {
        "graylog/context.json": json_bytes({
            "rule": plan.get("rule"), "context": plan.get("context") or {},
            "time_window": plan.get("time_window"),
        }),
        "resolver.json": json_bytes({
            "target_candidates": plan.get("target_candidates") or [],
            "client": plan.get("client") or {},
            "match_evidence": plan.get("match_evidence") or [],
        }),
        "velociraptor/collection.json": json_bytes({
            "case_id": case_id,
            "playbook": plan.get("playbook"),
            "generated_at": generated,
            "artifacts": [{key: value for key, value in item.items() if key != "rows"}
                          for item in collections],
        }),
        "velociraptor/errors.json": json_bytes(errors),
        "README.md": (
            f"# Автотриаж Velociraptor: кейс IRIS №{case_id}\n\n"
            f"- Сформировано (UTC): {generated}\n"
            f"- Правило: {(plan.get('rule') or {}).get('title') or '—'}\n"
            f"- Артефактов: {len(collections)}\n"
            f"- Ошибок: {len(errors)}\n\n"
            "Сбор запущен отдельным подтверждением event_id. Исходные строки находятся "
            "в `velociraptor/results/`, SHA-256 всех файлов — в `manifest.json`.\n"
        ).encode(),
    }
    for item in collections:
        safe_name = item["artifact"].replace(".", "_")
        files[f"velociraptor/results/{safe_name}.json"] = json_bytes(item.get("rows") or [])
    manifest = {
        "algorithm": "sha256", "generated_at": generated,
        "files": {
            name: {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
            for name, content in sorted(files.items())
        },
    }
    files["manifest.json"] = json_bytes(manifest)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(files.items()):
            archive.writestr(name, content)
    content = buffer.getvalue()
    return content, {
        "original_event_count": sum(item.get("row_count", 0) for item in collections),
        "context_event_count": 0,
        "collection_errors": len(errors),
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def execute_confirmed_plan(plan, *, case_id, confirm_event_id, collector,
                           output_dir, registry=None, pack=None, now=None):
    """Execute a freshly resolved plan after explicit out-of-band confirmation."""
    registry = registry or PlaybookRegistry.load()
    _require_confirmation(plan, case_id, confirm_event_id)
    artifacts, timeout, row_limit = _approved_artifacts(plan, registry)
    client_id = collector.validate_client_id((plan.get("client") or {}).get("client_id"))
    started = now or datetime.now(timezone.utc)
    collections, errors = [], []

    for artifact in artifacts:
        name = artifact["name"]
        started_us = time.time_ns() // 1000
        try:
            parameters = json.dumps(
                artifact["parameters"], ensure_ascii=True, separators=(",", ":"))
            vql = (
                "SELECT * FROM Artifact.Server.Utils.CollectClient("
                f"Client={_vql_string(client_id)}, ArtifactName={_vql_string(name)}, "
                f"Parameters={_vql_string(parameters)}) LIMIT {row_limit}")
            rows = collector.query(vql, timeout=timeout)
            flow = _flow_for_artifact(collector, client_id, name, started_us)
            flow_id = flow["session_id"]
            collections.append({
                "artifact": name,
                "parameters": artifact["parameters"],
                "flow_id": flow_id,
                "flow_created_time_us": flow.get("create_time"),
                "state": flow["state"],
                "row_count": len(rows),
                "total_collected_rows": flow.get("total_collected_rows"),
                "flow_link": collector.flow_link(client_id, flow_id),
                "rows": rows,
            })
        except Exception as error:
            errors.append({
                "artifact": name,
                "exception": type(error).__name__,
                "error": str(error)[:500],
            })

    generated = (now or datetime.now(timezone.utc)).isoformat()
    content, metadata = _zip_evidence(plan, case_id, collections, errors, generated)
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    event_id = str((plan.get("rule") or {}).get("event_id") or "")
    event_suffix = hashlib.sha256(event_id.encode()).hexdigest()[:12]
    metadata["filename"] = f"case-{case_id}-auto-triage-{stamp}-{event_suffix}.zip"
    metadata["generated_at"] = generated
    metadata["file_tags"] = "ticketbridge,evidence-pack,velociraptor,auto-triage"
    metadata["file_description"] = (
        f"Подтверждённый автотриаж Velociraptor; SHA-256 {metadata['sha256']}")

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    output = destination / metadata["filename"]
    output.write_bytes(content)
    output.chmod(0o600)

    successes = len(collections)
    status = ("completed" if not errors else "partial" if successes else "failed")
    result = {
        "status": status,
        "case_id": case_id,
        "client_id": client_id,
        "artifacts": [{key: value for key, value in item.items() if key != "rows"}
                      for item in collections],
        "errors": errors,
        "zip": {"path": str(output), "filename": metadata["filename"],
                "size": metadata["size"], "sha256": metadata["sha256"]},
        "execution": {"authorized": True, "requires_confirmation": False,
                      "flow_created": bool(collections)},
        "evidence": None,
        "evidence_error": None,
    }
    if pack is not None:
        try:
            result["evidence"] = pack.attach(case_id, content, metadata)
        except Exception as error:
            result["evidence_error"] = {
                "exception": type(error).__name__, "error": str(error)[:500]}
    return result
