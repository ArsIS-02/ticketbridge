import importlib.util
import json
from pathlib import Path
import sys


TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location("restore_graylog_mail", TOOLS / "restore_graylog_mail.py")
restore = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(restore)


def notification(identifier, title, kind="email-notification-v1"):
    return {"id": identifier, "title": title, "config": {"type": kind}}


def binding(identifier, parameters=None):
    return {"notification_id": identifier, "notification_parameters": parameters}


def definition(identifier, state="ENABLED", alert=True, notifications=None):
    return {
        "id": identifier,
        "title": identifier,
        "state": state,
        "alert": alert,
        "notifications": notifications or [],
        "_scope": "DEFAULT",
        "matched_at": None,
        "updated_at": "2026-11-11T00:00:00Z",
        "scheduler": None,
    }


def write_backup(path, definitions):
    path.mkdir()
    (path / "notifications-before.json").write_text(json.dumps([
        notification("mail-a", "Mail.ru Alert A"),
        notification("mail-b", "Mail.ru Alert B"),
        notification("digest", "Mail.ru Daily Digest"),
        notification("hook", "GLPI Ticket (TicketBridge)", "http-notification-v1"),
    ]), encoding="utf-8")
    (path / "definitions-before.json").write_text(json.dumps(definitions), encoding="utf-8")


def test_backups_are_merged_and_digests_are_not_restored(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    write_backup(first, [definition("one", notifications=[binding("hook"), binding("mail-a"), binding("digest")])])
    write_backup(second, [
        definition("one", notifications=[binding("hook"), binding("mail-a")]),
        definition("two", notifications=[binding("hook"), binding("mail-b")]),
    ])
    saved = restore.load_saved_bindings([first, second])
    assert {item["notification_id"] for item in saved["one"]} == {"mail-a"}
    assert {item["notification_id"] for item in saved["two"]} == {"mail-b"}


def test_targets_are_idempotent_and_require_current_ticketbridge_hook():
    saved = {"one": [binding("mail-a")], "two": [binding("mail-b")]}
    items = [
        definition("one", notifications=[binding("hook")]),
        definition("one-restored", notifications=[binding("hook"), binding("mail-a")]),
        definition("two", state="DISABLED", notifications=[binding("hook")]),
        definition("three", notifications=[binding("mail-a")]),
    ]
    assert [item["id"] for item in restore.targets(items, saved, "hook")] == ["one"]
    restored = definition("one", notifications=[binding("hook"), binding("mail-a")])
    assert restore.targets([restored], saved, "hook") == []


def test_update_preserves_current_bindings_and_drops_read_only_metadata():
    original = definition("one", notifications=[binding("hook"), binding("current"), binding("digest")])
    entity = restore.update_entity(original, [binding("mail-a")], "hook")
    assert [item["notification_id"] for item in entity["notifications"]] == [
        "hook", "current", "digest", "mail-a",
    ]
    assert not {"_scope", "matched_at", "updated_at", "scheduler"} & set(entity)
    assert len(original["notifications"]) == 3
