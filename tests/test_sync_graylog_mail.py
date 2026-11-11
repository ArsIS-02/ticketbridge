import importlib.util
from pathlib import Path
import sys


TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location("sync_graylog_mail", TOOLS / "sync_graylog_mail.py")
sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync)


def notification(identifier, title, kind="email-notification-v1"):
    return {"id": identifier, "title": title, "config": {"type": kind}}


def binding(identifier):
    return {"notification_id": identifier, "notification_parameters": None}


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


def test_only_instant_email_is_selected_digests_and_hook_are_kept():
    notifications = [
        notification("mail", "Mail.ru Alert Linux"),
        notification("digest", "Mail.ru Daily Digest"),
        notification("hook", "GLPI Ticket (TicketBridge)", "http-notification-v1"),
    ]
    assert sync.instant_mail_ids(notifications) == {"mail"}


def test_targets_require_enabled_iris_backed_alert_with_duplicate_mail():
    mail_ids = {"mail"}
    items = [
        definition("duplicate", notifications=[binding("hook"), binding("mail")]),
        definition("disabled", state="DISABLED", notifications=[binding("hook"), binding("mail")]),
        definition("not-alert", alert=False, notifications=[binding("hook"), binding("mail")]),
        definition("without-iris", notifications=[binding("mail")]),
        definition("iris-only", notifications=[binding("hook")]),
        definition("digest-kept", notifications=[binding("hook"), binding("digest")]),
    ]
    assert [item["id"] for item in sync.targets(items, mail_ids, "hook")] == ["duplicate"]


def test_update_entity_removes_only_instant_mail_and_preserves_metadata_rules():
    original = definition("duplicate", notifications=[
        binding("hook"), binding("mail"), binding("other-mail"), binding("digest"),
    ])
    entity = sync.update_entity(original, {"mail", "other-mail"}, "hook")
    assert [item["notification_id"] for item in entity["notifications"]] == ["hook", "digest"]
    assert not {"_scope", "matched_at", "updated_at", "scheduler"} & set(entity)
    assert len(original["notifications"]) == 4
