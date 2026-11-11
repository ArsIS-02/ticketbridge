import importlib.util
from pathlib import Path


MODULE = Path(__file__).resolve().parent.parent / "tools" / "sync_graylog_iris.py"
SPEC = importlib.util.spec_from_file_location("sync_graylog_iris", MODULE)
sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync)


def definition(identifier, state="ENABLED", alert=True, priority=1, notifications=None):
    return {
        "id": identifier,
        "title": identifier,
        "state": state,
        "alert": alert,
        "priority": priority,
        "notifications": notifications or [],
        "_scope": "DEFAULT",
        "matched_at": None,
        "updated_at": "2026-11-11T00:00:00Z",
        "scheduler": None,
    }


def test_targets_only_enabled_unbound_alerts():
    items = [
        definition("new-low"),
        definition("disabled", state="DISABLED"),
        definition("not-alert", alert=False),
        definition("already", notifications=[{"notification_id": "iris-hook"}]),
    ]
    assert [item["id"] for item in sync.targets(items, "iris-hook")] == ["new-low"]


def test_update_entity_preserves_existing_bindings_and_drops_metadata():
    original = definition("medium", priority=2,
                          notifications=[{"notification_id": "mail", "notification_parameters": None}])
    entity = sync.update_entity(original, "iris-hook")
    assert [item["notification_id"] for item in entity["notifications"]] == ["mail", "iris-hook"]
    assert entity["priority"] == 2 and entity["state"] == "ENABLED"
    assert not {"_scope", "matched_at", "updated_at", "scheduler"} & set(entity)
    assert len(original["notifications"]) == 1
