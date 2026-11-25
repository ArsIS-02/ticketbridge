#!/usr/bin/env python3
"""Asynchronous, deduplicated /hook scheduling for opt-in automatic triage.

Default off performs no DB, network, thread or collection operation. dry_run
only resolves clients and logs a plan. on executes only after IRIS correlation
has supplied an existing case_id. There are no automatic retries.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import threading
import time

import auto_triage
import auto_triage_execution
from collection_playbooks import PlaybookRegistry
from iris_evidence_pack import EvidencePack
from velociraptor_evidence import VelociraptorCollector

_ACTIVE_LOCK = threading.Lock()
_ACTIVE = {"count": 0}


def _emit(log, short, **fields):
    if not log:
        return
    try:
        log(short, tool="ticketbridge", **fields)
    except Exception:
        pass


def _connect(db_path):
    con = sqlite3.connect(db_path, timeout=30)
    con.execute("""CREATE TABLE IF NOT EXISTS auto_triage_runs(
        event_id TEXT PRIMARY KEY,
        event_definition_id TEXT NOT NULL,
        case_id INTEGER NOT NULL,
        status TEXT NOT NULL,
        created_ts REAL NOT NULL,
        finished_ts REAL,
        result_json TEXT)""")
    return con


def _case_for_alert(con, alert_id):
    try:
        identifier = int(alert_id)
    except (TypeError, ValueError):
        return None
    row = con.execute(
        "SELECT case_id FROM iris_corr WHERE alert_id=? AND escalated=1"
        " AND case_id IS NOT NULL ORDER BY last_ts DESC LIMIT 1",
        (identifier,)).fetchone()
    return int(row[0]) if row and row[0] is not None else None


def _max_parallel():
    try:
        return min(4, max(1, int(os.environ.get("TB_VR_AUTO_TRIAGE_MAX_PARALLEL", "1"))))
    except ValueError:
        return 1


def _reserve():
    with _ACTIVE_LOCK:
        if _ACTIVE["count"] >= _max_parallel():
            return False
        _ACTIVE["count"] += 1
        return True


def _release():
    with _ACTIVE_LOCK:
        _ACTIVE["count"] = max(0, _ACTIVE["count"] - 1)


def _record(db_path, event_id, status, result):
    con = _connect(db_path)
    try:
        con.execute(
            "UPDATE auto_triage_runs SET status=?, finished_ts=?, result_json=?"
            " WHERE event_id=?",
            (status, time.time(), json.dumps(result, ensure_ascii=False, default=str), event_id))
        con.commit()
    finally:
        con.close()


def _collector(env):
    return VelociraptorCollector(
        binary=env.get("TB_VR_BINARY", "/opt/velociraptor/velociraptor"),
        api_config=env.get("TB_VR_API_CONFIG", ""),
        gui_url=env.get("TB_VR_GUI_URL", "https://velociraptor.example.test"),
        creator=env.get("TB_VR_CREATOR", "ticketbridge-collector"),
        timeout=int(env.get("TB_VR_TIMEOUT", "300")),
    )


def _worker(event, case_id, alert_id, db_path, claimed, log):
    event_id = str(event.get("id") or "")
    rule_id = str(event.get("event_definition_id") or "")
    mode = auto_triage.AutoTriagePolicy.from_env(os.environ).mode
    try:
        env = dict(os.environ)
        registry = PlaybookRegistry.load()
        collector = _collector(env)
        context = {"case_id": case_id, "alert_id": alert_id}
        plan = auto_triage.plan_from_environment(
            event, env, collector=collector, registry=registry, context=context)
        auto = plan.get("auto_triage") or {}
        if plan.get("status") != "dry_run" or auto.get("eligible") is not True:
            if claimed:
                _record(db_path, event_id, "blocked", {
                    "status": plan.get("status"), "auto_triage": auto})
            _emit(log, "TicketBridge: авто-триаж не допущен",
                  tb_event="auto_triage_blocked", event_id=event_id,
                  event_definition_id=rule_id, case_id=case_id or 0,
                  triage_status=plan.get("status"),
                  blocking_reasons=",".join(auto.get("blocking_reasons") or []))
            return

        if mode == "dry_run":
            _emit(log, "TicketBridge: dry-run авто-триажа построен",
                  tb_event="auto_triage_dry_run", event_id=event_id,
                  event_definition_id=rule_id, case_id=case_id or 0,
                  artifact_count=len(plan.get("artifacts") or []))
            return

        pack = EvidencePack(env.get("TB_IRIS_URL", ""), env.get("TB_IRIS_KEY", ""))
        output_dir = env.get(
            "TB_VR_AUTO_TRIAGE_OUTPUT",
            str(Path(db_path).resolve().parent / "auto-triage-evidence"))
        result = auto_triage_execution.execute_confirmed_plan(
            plan, case_id=case_id, confirm_event_id=event_id,
            collector=collector, output_dir=output_dir, registry=registry, pack=pack)
        status = result["status"]
        if result.get("evidence_error"):
            status = "evidence_error"
        _record(db_path, event_id, status, result)
        evidence = result.get("evidence") or {}
        _emit(log, f"TicketBridge: авто-триаж завершён со статусом {status}",
              tb_event="auto_triage_finished", event_id=event_id,
              event_definition_id=rule_id, case_id=case_id,
              triage_status=status, artifact_count=len(result.get("artifacts") or []),
              collection_errors=len(result.get("errors") or []),
              evidence_id=evidence.get("evidence_id") or 0,
              filename=(result.get("zip") or {}).get("filename") or "")
    except Exception as error:
        failure = {"exception": type(error).__name__, "error": str(error)[:500]}
        if claimed:
            try:
                _record(db_path, event_id, "error", failure)
            except Exception:
                pass
        _emit(log, "TicketBridge: ошибка авто-триажа",
              tb_event="auto_triage_error", event_id=event_id,
              event_definition_id=rule_id, case_id=case_id or 0,
              error_type=type(error).__name__)
    finally:
        _release()


def maybe_start(event, alert_id, db_path, log=None):
    """Return a scheduling status; never propagate a triage error to /hook."""
    policy = auto_triage.AutoTriagePolicy.from_env(os.environ)
    rule_id = str(event.get("event_definition_id") or "")
    event_id = str(event.get("id") or "")
    if policy.mode == "off":
        return "disabled"
    if policy.mode not in auto_triage.SUPPORTED_MODES:
        return "config_error"
    if rule_id not in policy.opted_in_rules:
        return "rule_not_opted_in"
    if policy.mode == "on" and not event_id:
        return "missing_event_id"
    if not _reserve():
        return "busy"

    claimed = False
    handed_off = False
    try:
        con = _connect(db_path)
        try:
            case_id = _case_for_alert(con, alert_id)
            if policy.mode == "on" and not case_id:
                return "case_not_available"
            if policy.mode == "on":
                try:
                    con.execute(
                        "INSERT INTO auto_triage_runs(event_id, event_definition_id,"
                        " case_id, status, created_ts) VALUES(?,?,?,?,?)",
                        (event_id, rule_id, case_id, "running", time.time()))
                    con.commit()
                    claimed = True
                except sqlite3.IntegrityError:
                    return "duplicate"
        finally:
            con.close()

        thread = threading.Thread(
            target=_worker, args=(event, case_id, alert_id, db_path, claimed, log),
            daemon=True, name=f"auto-triage-{event_id or 'dry-run'}")
        try:
            thread.start()
            handed_off = True
        except Exception:
            if claimed:
                _record(db_path, event_id, "error", {"exception": "thread_start"})
            raise
        return "dry_run_started" if policy.mode == "dry_run" else "started"
    except Exception as error:
        _emit(log, "TicketBridge: не удалось запланировать авто-триаж",
              tb_event="auto_triage_schedule_error", event_id=event_id,
              event_definition_id=rule_id, error_type=type(error).__name__)
        return "schedule_error"
    finally:
        if not handed_off:
            _release()
