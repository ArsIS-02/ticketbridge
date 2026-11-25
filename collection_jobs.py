#!/usr/bin/env python3
"""Persistent background jobs for confirmed Velociraptor collections.

The reviewed collectors remain synchronous inside their worker thread. This
module only adds lifecycle persistence, duplicate suppression and resumable UI
status. A process restart marks unfinished jobs as interrupted instead of
silently leaving them "running" or repeating an evidence collection.
"""
from __future__ import annotations

import json
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
               started=False, finished=False):
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


class CollectionJobManager:
    def __init__(self, db_path, *, case_runner, alert_runner, notify=None,
                 max_parallel=2, store=None):
        self.store = store or CollectionJobStore(db_path)
        self.case_runner = case_runner
        self.alert_runner = alert_runner
        self.notify = notify
        self.max_parallel = max(1, min(4, int(max_parallel)))
        self._lock = threading.Lock()
        self._active = 0

    def _reserve(self):
        with self._lock:
            if self._active >= self.max_parallel:
                raise CollectionJobBusy("The manual collection worker limit is reached")
            self._active += 1

    def _release(self):
        with self._lock:
            self._active = max(0, self._active - 1)

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
            while cause is not None:
                candidate = getattr(cause, "collection_result", None)
                if candidate is not None:
                    delivery_result = candidate
                    break
                cause = cause.__cause__
            status = "evidence_error" if delivery_result is not None else "error"
            finished = self.store.update(
                job_id, status, case_id=case_id, result=delivery_result,
                error=f"{type(error).__name__}: {str(error)[:700]}", finished=True)
            self._notify(finished)
        finally:
            self._release()
