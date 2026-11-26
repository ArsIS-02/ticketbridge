#!/usr/bin/env python3
"""Persistent background jobs for confirmed Velociraptor collections.

The reviewed collectors remain synchronous inside their worker thread. This
module only adds lifecycle persistence, duplicate suppression and resumable UI
status. A process restart marks unfinished jobs as interrupted instead of
silently leaving them "running" or repeating an evidence collection.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import threading
import time
import uuid

ACTIVE_STATUSES = ("queued", "collecting", "uploading")
TERMINAL_STATUSES = ("completed", "partial", "failed", "evidence_error", "error")


class CollectionJobBusy(RuntimeError):
    pass


class CollectionJobStore:
    def __init__(self, db_path):
        self.db_path = str(db_path)
        self._initialize()

    def _connect(self):
        con = sqlite3.connect(self.db_path, timeout=30)
        con.row_factory = sqlite3.Row
        con.execute("""CREATE TABLE IF NOT EXISTS velociraptor_collection_jobs(
            job_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL CHECK(kind IN ('alert', 'case')),
            target_id INTEGER NOT NULL,
            case_id INTEGER,
            asset_id INTEGER NOT NULL,
            client_id TEXT NOT NULL,
            platform TEXT NOT NULL,
            requested_json TEXT NOT NULL,
            status TEXT NOT NULL,
            created_ts REAL NOT NULL,
            started_ts REAL,
            finished_ts REAL,
            updated_ts REAL NOT NULL,
            result_json TEXT,
            error TEXT
        )""")
        con.execute("""CREATE INDEX IF NOT EXISTS idx_vr_collection_jobs_target
            ON velociraptor_collection_jobs(kind, target_id, created_ts DESC)""")
        con.execute("""CREATE INDEX IF NOT EXISTS idx_vr_collection_jobs_case
            ON velociraptor_collection_jobs(case_id, created_ts DESC)""")
        return con

    def _initialize(self):
        con = self._connect()
        try:
            now = time.time()
            con.execute(
                f"""UPDATE velociraptor_collection_jobs
                    SET status='error', finished_ts=?, updated_ts=?,
                        error='TicketBridge restarted before this collection completed; '
                           || 'verify the Flow before starting a new collection'
                    WHERE status IN ({','.join('?' for _ in ACTIVE_STATUSES)})""",
                (now, now, *ACTIVE_STATUSES))
            con.commit()
        finally:
            con.close()

    @staticmethod
    def _public(row):
        if row is None:
            return None
        item = dict(row)
        item["requested_artifacts"] = json.loads(item.pop("requested_json"))
        raw_result = item.pop("result_json")
        item["result"] = json.loads(raw_result) if raw_result else None
        return item

    def get(self, job_id):
        con = self._connect()
        try:
            row = con.execute(
                "SELECT * FROM velociraptor_collection_jobs WHERE job_id=?",
                (str(job_id),)).fetchone()
            return self._public(row)
        finally:
            con.close()

    def latest(self, kind, target_id):
        if kind not in ("alert", "case"):
            raise ValueError("Invalid collection job kind")
        con = self._connect()
        try:
            row = con.execute(
                """SELECT * FROM velociraptor_collection_jobs
                   WHERE kind=? AND target_id=? ORDER BY created_ts DESC LIMIT 1""",
                (kind, int(target_id))).fetchone()
            return self._public(row)
        finally:
            con.close()

    def for_case(self, case_id, limit=20):
        """Return alert- and incident-level jobs linked to one incident."""
        limit = max(1, min(50, int(limit)))
        con = self._connect()
        try:
            rows = con.execute(
                """SELECT * FROM velociraptor_collection_jobs
                   WHERE case_id=? ORDER BY created_ts DESC LIMIT ?""",
                (int(case_id), limit)).fetchall()
            return [self._public(row) for row in rows]
        finally:
            con.close()

    def active_for_target(self, con, kind, target_id):
        return con.execute(
            f"""SELECT * FROM velociraptor_collection_jobs
                WHERE kind=? AND target_id=?
                  AND status IN ({','.join('?' for _ in ACTIVE_STATUSES)})
                ORDER BY created_ts DESC LIMIT 1""",
            (kind, int(target_id), *ACTIVE_STATUSES)).fetchone()

    def create(self, kind, target_id, asset_id, client_id, platform, artifacts):
        if kind not in ("alert", "case"):
            raise ValueError("Invalid collection job kind")
        now = time.time()
        job_id = uuid.uuid4().hex
        con = self._connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            active = self.active_for_target(con, kind, target_id)
            if active is not None:
                con.rollback()
                return self._public(active), True
            con.execute(
                """INSERT INTO velociraptor_collection_jobs(
                    job_id, kind, target_id, case_id, asset_id, client_id,
                    platform, requested_json, status, created_ts, updated_ts)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (job_id, kind, int(target_id),
                 int(target_id) if kind == "case" else None,
                 int(asset_id), str(client_id), str(platform),
                 json.dumps(list(artifacts), ensure_ascii=False), "queued", now, now))
            con.commit()
        finally:
            con.close()
        return self.get(job_id), False

    def update(self, job_id, status, *, case_id=None, result=None, error=None,
               started=False, finished=False, clear_finished=False):
        now = time.time()
        fields = ["status=?", "updated_ts=?"]
        values = [status, now]
        if case_id is not None:
            fields.append("case_id=?")
            values.append(int(case_id))
        if result is not None:
            fields.append("result_json=?")
            values.append(json.dumps(result, ensure_ascii=False, default=str))
        if error is not None:
            fields.append("error=?")
            values.append(str(error)[:800])
        if started:
            fields.append("started_ts=?")
            values.append(now)
        if finished:
            fields.append("finished_ts=?")
            values.append(now)
        if clear_finished:
            fields.append("finished_ts=NULL")
        values.append(str(job_id))
        con = self._connect()
        try:
            con.execute(
                f"UPDATE velociraptor_collection_jobs SET {','.join(fields)} WHERE job_id=?",
                values)
            con.commit()
        finally:
            con.close()
        return self.get(job_id)


class CollectionJobRecoveryError(RuntimeError):
    """The requested job cannot use the saved Evidence recovery package."""


class CollectionJobManager:
    def __init__(self, db_path, *, case_runner, alert_runner, notify=None,
                 max_parallel=2, store=None, evidence_retry_runner=None,
                 package_dir=None):
        self.store = store or CollectionJobStore(db_path)
        self.case_runner = case_runner
        self.alert_runner = alert_runner
        self.evidence_retry_runner = evidence_retry_runner
        self.notify = notify
        self.max_parallel = max(1, min(4, int(max_parallel)))
        self.package_dir = Path(package_dir) if package_dir else (
            Path(db_path).resolve().parent / "velociraptor-packages")
        self.package_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.package_dir.chmod(0o700)
        self._lock = threading.Lock()
        self._active = 0
        self._retrying = set()

    def _reserve(self):
        with self._lock:
            if self._active >= self.max_parallel:
                raise CollectionJobBusy("The manual collection worker limit is reached")
            self._active += 1

    def _release(self):
        with self._lock:
            self._active = max(0, self._active - 1)

    def _package_path(self, job_id):
        job_id = str(job_id)
        if (len(job_id) != 32
                or any(character not in "0123456789abcdef" for character in job_id)):
            raise ValueError("Invalid collection job_id")
        return self.package_dir / f"{job_id}.zip"

    def _save_package(self, job_id, content):
        if not isinstance(content, (bytes, bytearray)) or not content:
            raise ValueError("Recovery ZIP content is empty or invalid")
        path = self._package_path(job_id)
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            path.chmod(0o600)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        return path

    def _discard_package(self, job_id):
        try:
            self._package_path(job_id).unlink()
        except FileNotFoundError:
            pass
        except OSError:
            # Evidence is already attached; a stale private file cannot change
            # the persisted outcome or make a second upload look necessary.
            pass

    def start_case(self, case_id, asset_id, client_id, platform, artifacts):
        return self._start("case", case_id, asset_id, client_id, platform, artifacts)

    def start_alert(self, alert_id, asset_id, client_id, platform, artifacts):
        return self._start("alert", alert_id, asset_id, client_id, platform, artifacts)

    def _start(self, kind, target_id, asset_id, client_id, platform, artifacts):
        job, duplicate = self.store.create(
            kind, target_id, asset_id, client_id, platform, artifacts)
        if duplicate:
            return job, True
        try:
            self._reserve()
        except CollectionJobBusy:
            self.store.update(job["job_id"], "error",
                              error="The manual collection worker limit is reached; retry later",
                              finished=True)
            raise
        try:
            thread = threading.Thread(
                target=self._run, args=(job["job_id"],), daemon=True,
                name=f"vr-collection-{job['job_id'][:12]}")
            thread.start()
        except Exception:
            self._release()
            self.store.update(job["job_id"], "error",
                              error="Could not start the collection worker", finished=True)
            raise
        return self.store.get(job["job_id"]), False

    def _notify(self, job):
        if not self.notify:
            return
        try:
            self.notify(job)
        except Exception:
            # Notification must never change the persisted collection outcome.
            pass

    def retry_evidence(self, job_id):
        """Upload the saved ZIP only; this path has no access to a collector."""
        job_id = str(job_id)
        with self._lock:
            if job_id in self._retrying:
                raise CollectionJobBusy("Evidence recovery is already running for this job")
            self._retrying.add(job_id)
        try:
            job = self.store.get(job_id)
            if not job:
                raise KeyError(job_id)
            if job["status"] != "evidence_error":
                raise CollectionJobRecoveryError(
                    "Only a job in evidence_error can be retried without a new collection")
            original = job.get("result") or {}
            if original.get("recovery_available") is not True:
                raise CollectionJobRecoveryError(
                    "This job has no saved recovery ZIP; review it before a new collection")
            package_path = self._package_path(job_id)
            if not package_path.is_file():
                raise CollectionJobRecoveryError(
                    "The saved recovery ZIP is missing; review it before a new collection")
            if not self.evidence_retry_runner:
                raise CollectionJobRecoveryError("Evidence recovery is not configured")

            self.store.update(job_id, "uploading", case_id=job.get("case_id"),
                              error="", clear_finished=True)
            try:
                result = self.evidence_retry_runner(job, package_path)
                if not isinstance(result, dict):
                    raise RuntimeError("Evidence recovery returned an invalid result")
                status = result.get("status")
                if status not in ("completed", "partial", "failed"):
                    raise RuntimeError("Evidence recovery returned an invalid terminal status")
                if status != original.get("status"):
                    raise RuntimeError("Evidence recovery changed the collection status")
                result = dict(result)
                result["recovery_available"] = False
                case_id = result.get("case_id") or job.get("case_id")
                finished = self.store.update(
                    job_id, status, case_id=case_id, result=result,
                    error="", finished=True)
                self._discard_package(job_id)
                self._notify(finished)
                return finished
            except Exception as error:
                current = self.store.get(job_id) or job
                recovery = current.get("result") or original
                recovery["recovery_available"] = package_path.is_file()
                finished = self.store.update(
                    job_id, "evidence_error", case_id=current.get("case_id"),
                    result=recovery,
                    error=f"{type(error).__name__}: {str(error)[:700]}", finished=True)
                self._notify(finished)
                return finished
        finally:
            with self._lock:
                self._retrying.discard(job_id)

    def _run(self, job_id):
        job = self.store.get(job_id)
        if not job:
            self._release()
            return
        try:
            self.store.update(job_id, "collecting", started=True)
            args = (job["target_id"] if job["kind"] == "alert" else job["case_id"],
                    job["asset_id"], job["client_id"], job["platform"],
                    job["requested_artifacts"])
            runner = self.alert_runner if job["kind"] == "alert" else self.case_runner

            def progress(status):
                if status == "uploading":
                    current = self.store.get(job_id) or {}
                    self.store.update(job_id, "uploading",
                                      case_id=current.get("case_id"))

            result = runner(*args, progress=progress)
            if not isinstance(result, dict):
                raise RuntimeError("Collection runner returned an invalid result")
            case_id = result.get("case_id") or job.get("case_id")
            status = result.get("status")
            if status not in ("completed", "partial", "failed"):
                raise RuntimeError("Collection runner returned an invalid terminal status")
            finished = self.store.update(
                job_id, status, case_id=case_id, result=result, error="", finished=True)
            self._notify(finished)
        except Exception as error:
            current = self.store.get(job_id) or job
            case_id = getattr(error, "case_id", None) or current.get("case_id")
            cause = error
            delivery_result = None
            package_content = None
            while cause is not None:
                candidate = getattr(cause, "collection_result", None)
                if candidate is not None and delivery_result is None:
                    delivery_result = candidate
                content = getattr(cause, "package_content", None)
                if content is not None and package_content is None:
                    package_content = content
                cause = cause.__cause__
            recovery_error = None
            if delivery_result is not None and package_content is not None:
                delivery_result = dict(delivery_result)
                try:
                    self._save_package(job_id, package_content)
                    delivery_result["recovery_available"] = True
                except (OSError, ValueError) as save_error:
                    delivery_result["recovery_available"] = False
                    recovery_error = save_error
            status = "evidence_error" if delivery_result is not None else "error"
            message = f"{type(error).__name__}: {str(error)[:700]}"
            if recovery_error is not None:
                message += f"; recovery ZIP save failed: {str(recovery_error)[:200]}"
            finished = self.store.update(
                job_id, status, case_id=case_id, result=delivery_result,
                error=message[:800], finished=True)
            self._notify(finished)
        finally:
            self._release()
