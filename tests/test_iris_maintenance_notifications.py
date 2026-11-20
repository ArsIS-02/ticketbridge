import ast
import json
from pathlib import Path
from types import SimpleNamespace


SOURCE = (Path(__file__).resolve().parent.parent / "deploy" / "iris" / "alerts.py").read_text()
TREE = ast.parse(SOURCE)
HELPER = next(node for node in TREE.body
              if isinstance(node, ast.FunctionDef) and node.name == "_maintenance_email_suppressed")
NAMESPACE = {"json": json}
exec(compile(ast.Module(body=[HELPER], type_ignores=[]), "alerts.py", "exec"), NAMESPACE)
suppressed = NAMESPACE["_maintenance_email_suppressed"]


UNSET = object()


def alert(active="true", tags="graylog,ticketbridge,maintenance,hostdeck", content=UNSET):
    if content is UNSET:
        content = {"fields": {"maintenance_active": active}}
    return SimpleNamespace(alert_source_content=content, alert_tags=tags)


def test_active_hostdeck_maintenance_suppresses_only_email():
    assert suppressed(alert()) is True
    assert "default_channels={'in_app': True,\n                                  'email': not _maintenance_email_suppressed(alert)}" in SOURCE


def test_expired_window_and_normal_availability_keep_email():
    assert suppressed(alert(active="false")) is False
    assert suppressed(alert(content={"fields": {}})) is False


def test_generic_maintenance_tag_without_source_confirmation_is_not_enough():
    assert suppressed(alert(content={"fields": {"maintenance_active": True}},
                            tags="maintenance")) is False
    assert suppressed(alert(active="true", tags="maintenance")) is False


def test_security_and_malformed_content_keep_email():
    assert suppressed(alert(content={"fields": {"host": "server-01.example.test"}})) is False
    assert suppressed(alert(content="not-json")) is False
    assert suppressed(alert(content=None)) is False
    assert suppressed(alert(content=[])) is False
