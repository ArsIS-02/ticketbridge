import json
from pathlib import Path
import sys
import threading
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import alert_collection
import collection_jobs
import manual_collection

CLIENT = "C.0123456789abcdef"
ARTIFACTS = ["Generic.Client.Info"]


def wait_for(call, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = call()
        if value:
            return value
        time.sleep(0.01)
    raise AssertionError("condition was not reached")


def result(case_id=73, status="completed"):
    return {
        "case_id": case_id, "status": status, "platform": "linux",
        "batch_id": "batch-1", "requested_artifacts": ARTIFACTS,
        "artifacts": [{"artifact": ARTIFACTS[0], "flow_id": "F.TEST",
                       "flow_link": "https://velociraptor.example.test/F.TEST",
                       "row_count": 1}],
        "errors": [], "evidence_id": 17, "filename": "case-73-test.zip",
        "sha256": "abc123",
    }


def manager(tmp_path, case_runner, alert_runner=None, notify=None, max_parallel=2):
    return collection_jobs.CollectionJobManager(
        tmp_path / "state.db", case_runner=case_runner,
        alert_runner=alert_runner or case_runner, notify=notify,
        max_parallel=max_parallel)


def test_case_job_finishes_in_background_with_persistent_result(tmp_path):
    stages = []
    release = threading.Event()

    def run(case_id, asset_id, client_id, platform, artifacts, progress):
        stages.append(("collecting", case_id, asset_id, client_id, platform, artifacts))
        release.wait(2)
        progress("uploading")
        return result(case_id)

    jobs = manager(tmp_path, run)
    job, duplicate = jobs.start_case(73, 42, CLIENT, "linux", ARTIFACTS)
    assert duplicate is False
    assert job["status"] in collection_jobs.ACTIVE_STATUSES
    wait_for(lambda: jobs.store.get(job["job_id"])["status"] == "collecting")
    release.set()
    final = wait_for(lambda: (jobs.store.get(job["job_id"])["status"] == "completed")
                     and jobs.store.get(job["job_id"]))
    assert final["case_id"] == 73
    assert final["result"]["evidence_id"] == 17
    assert final["finished_ts"] is not None
    assert stages == [("collecting", 73, 42, CLIENT, "linux", ARTIFACTS)]


def test_parallel_duplicate_reuses_job_and_later_confirmed_run_is_allowed(tmp_path):
    release = threading.Event()
    calls = []

    def run(case_id, asset_id, client_id, platform, artifacts, progress):
        calls.append(case_id)
        release.wait(2)
        return result(case_id)

    jobs = manager(tmp_path, run)
    first, _ = jobs.start_case(73, 42, CLIENT, "linux", ARTIFACTS)
    wait_for(lambda: calls)
    second, duplicate = jobs.start_case(73, 42, CLIENT, "linux", ARTIFACTS)
    assert duplicate is True and second["job_id"] == first["job_id"]
    release.set()
    wait_for(lambda: jobs.store.get(first["job_id"])["status"] == "completed")
    third, duplicate = jobs.start_case(73, 42, CLIENT, "linux", ARTIFACTS)
    assert duplicate is False and third["job_id"] != first["job_id"]
    wait_for(lambda: jobs.store.get(third["job_id"])["status"] == "completed")
    assert calls == [73, 73]


def test_alert_failure_is_visible_and_notification_cannot_change_outcome(tmp_path):
    notified = []

    def fail(alert_id, asset_id, client_id, platform, artifacts, progress):
        raise alert_collection.AlertCollectionError(
            "synthetic collector outage", status=502, alert_id=alert_id, case_id=91)

    jobs = manager(tmp_path, fail, notify=lambda job: notified.append(job))
    job, _ = jobs.start_alert(53, 42, CLIENT, "linux", ARTIFACTS)
    final = wait_for(lambda: (jobs.store.get(job["job_id"])["status"] == "error")
                     and jobs.store.get(job["job_id"]))
    assert final["case_id"] == 91
    assert "synthetic collector outage" in final["error"]
    assert notified[0]["job_id"] == job["job_id"]


def test_evidence_upload_error_preserves_collection_metadata(tmp_path):
    def fail(case_id, asset_id, client_id, platform, artifacts, progress):
        metadata = result(case_id)
        metadata["evidence_id"] = None
        error = manual_collection.EvidenceDeliveryError("upload unavailable", metadata)
        raise error

    jobs = manager(tmp_path, fail)
    job, _ = jobs.start_case(73, 42, CLIENT, "linux", ARTIFACTS)
    final = wait_for(lambda: (jobs.store.get(job["job_id"])["status"] == "evidence_error")
                     and jobs.store.get(job["job_id"]))
    assert final["result"]["sha256"] == "abc123"
    assert final["result"]["evidence_id"] is None


def test_restart_marks_unfinished_job_interrupted_without_repeating_it(tmp_path):
    store = collection_jobs.CollectionJobStore(tmp_path / "state.db")
    job, duplicate = store.create("case", 73, 42, CLIENT, "linux", ARTIFACTS)
    assert duplicate is False
    store.update(job["job_id"], "collecting", started=True)
    reopened = collection_jobs.CollectionJobStore(tmp_path / "state.db")
    final = reopened.get(job["job_id"])
    assert final["status"] == "error"
    assert "restarted" in final["error"]
    assert final["finished_ts"] is not None


def test_worker_limit_returns_busy_and_records_error(tmp_path):
    release = threading.Event()

    def run(case_id, asset_id, client_id, platform, artifacts, progress):
        release.wait(2)
        return result(case_id)

    jobs = manager(tmp_path, run, max_parallel=1)
    first, _ = jobs.start_case(73, 42, CLIENT, "linux", ARTIFACTS)
    with pytest.raises(collection_jobs.CollectionJobBusy):
        jobs.start_case(74, 43, CLIENT, "linux", ARTIFACTS)
    latest = jobs.store.latest("case", 74)
    assert latest["status"] == "error" and "worker limit" in latest["error"]
    release.set()
    wait_for(lambda: jobs.store.get(first["job_id"])["status"] == "completed")


def test_progress_and_delivery_error_from_real_pack_boundary(tmp_path):
    stages = []

    class Pack:
        def attach(self, case_id, content, metadata):
            raise RuntimeError("IRIS unavailable")

    class Collector:
        creator = "test"
        timeout = 1

        def flow_link(self, client_id, flow_id):
            return f"https://vr/{client_id}/{flow_id}"

    collection = {
        "status": "completed", "client_id": CLIENT, "platform": "linux",
        "requested_artifacts": ARTIFACTS,
        "parameter_window": {"start": "start", "end": "end"},
        "started_at": "start", "artifacts": [], "errors": [],
    }
    original = manual_collection.collect_many
    original_pack = manual_collection.build_multi_pack
    try:
        manual_collection.collect_many = lambda *args, **kwargs: collection
        manual_collection.build_multi_pack = lambda *args, **kwargs: (
            b"zip", {"filename": "test.zip", "size": 3, "sha256": "abc"},
            {"status": "completed"})
        with pytest.raises(manual_collection.EvidenceDeliveryError) as caught:
            manual_collection.collect_many_and_attach(
                73, CLIENT, "linux", ARTIFACTS, pack=Pack(), collector=Collector(),
                progress=stages.append)
    finally:
        manual_collection.collect_many = original
        manual_collection.build_multi_pack = original_pack
    assert stages == ["uploading"]
    assert caught.value.collection_result["filename"] == "test.zip"
