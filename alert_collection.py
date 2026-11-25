#!/usr/bin/env python3
"""Manual Velociraptor collection initiated from an IRIS alert.

The selected asset must belong to the alert. An existing linked incident is
reused; otherwise the alert is escalated once before collection. Only parallel
runs for the same alert are blocked: a later, explicitly confirmed run is valid.
"""
from __future__ import annotations

import threading


class AlertCollectionError(RuntimeError):
    def __init__(self, message, status=400, alert_id=None, case_id=None,
                 case_created=False):
        super().__init__(message)
        self.status = status
        self.alert_id = alert_id
        self.case_id = case_id
        self.case_created = case_created


class AlertCollectionInProgress(AlertCollectionError):
    def __init__(self, alert_id):
        super().__init__(
            f"A Velociraptor collection is already running for alert #{alert_id}",
            status=409, alert_id=alert_id)


_ACTIVE_ALERTS = set()
_ACTIVE_LOCK = threading.Lock()


def _linked_case_id(alert):
    cases = alert.get("cases") or []
    if not isinstance(cases, list):
        raise AlertCollectionError("IRIS returned an invalid linked incident list")
    for value in cases:
        try:
            case_id = int(value)
        except (TypeError, ValueError):
            continue
        if case_id > 0:
            return case_id
    return None


def _selected_asset(alert, asset_id):
    assets = alert.get("assets") or []
    if not isinstance(assets, list):
        raise AlertCollectionError("IRIS returned an invalid alert asset list")
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        try:
            matches = int(asset.get("asset_id")) == asset_id
        except (TypeError, ValueError):
            matches = False
        if matches:
            return asset
    raise AlertCollectionError("The selected asset does not belong to this alert")


def collect_from_alert(alert_id, asset_id, client_id, platform, artifacts,
                       iris_request, escalate, collect):
    """Resolve an alert to an incident and run the reviewed multi-collection.

    Dependencies are supplied by the caller so HTTP tests can replace IRIS and
    Velociraptor without network access. The active-run guard covers escalation
    as well as collection, preventing double-click creation of two incidents.
    """
    with _ACTIVE_LOCK:
        if alert_id in _ACTIVE_ALERTS:
            raise AlertCollectionInProgress(alert_id)
        _ACTIVE_ALERTS.add(alert_id)

    case_id = None
    case_created = False
    try:
        ok, alert = iris_request("GET", f"/api/v2/alerts/{alert_id}")
        if not ok or not isinstance(alert, dict):
            raise AlertCollectionError(
                f"Could not load IRIS alert #{alert_id}: {str(alert)[:200]}",
                status=502, alert_id=alert_id)
        asset = _selected_asset(alert, asset_id)
        case_id = _linked_case_id(alert)

        if case_id is None:
            title = str(alert.get("alert_title") or f"Alert #{alert_id}").strip()
            note = (f"Ручной триаж Velociraptor запущен из алерта #{alert_id}. "
                    f"Выбран актив {asset.get('asset_name') or asset_id}; "
                    "результат будет загружен в Evidence.")
            asset_uuid = str(asset.get("asset_uuid") or "").strip()
            imported_assets = [asset_uuid] if asset_uuid else []
            case_id, info = escalate(
                alert_id, title, note,
                tags="ticketbridge,velociraptor,manual-triage",
                assets=imported_assets)
            try:
                case_id = int(case_id)
            except (TypeError, ValueError):
                case_id = None
            if case_id is None or case_id <= 0:
                raise AlertCollectionError(
                    f"Could not escalate alert #{alert_id}: {str(info)[:200]}",
                    status=502, alert_id=alert_id)
            case_created = True

        try:
            result = collect(case_id, client_id, platform, artifacts, asset_id=asset_id)
        except Exception as error:
            raise AlertCollectionError(
                f"Velociraptor collection failed: {str(error)[:800]}",
                status=502, alert_id=alert_id, case_id=case_id,
                case_created=case_created) from error
        if not isinstance(result, dict):
            raise AlertCollectionError(
                "Velociraptor collector returned an invalid result", status=502,
                alert_id=alert_id, case_id=case_id, case_created=case_created)
        return {**result, "alert_id": alert_id, "case_id": case_id,
                "case_created": case_created}
    finally:
        with _ACTIVE_LOCK:
            _ACTIVE_ALERTS.discard(alert_id)
