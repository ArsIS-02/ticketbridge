from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app


def test_redos_workstation_is_linux_computer_even_with_server_profile():
    info = {"name": "RedOS-Workstation", "os": "linux", "profile": "server"}
    assert app._asset_type_for(info) == app.ASSET_TYPE_LINUX_COMPUTER


def test_linux_server_remains_server():
    info = {"name": "redos-server.monitoring.test", "os": "linux", "profile": "server"}
    assert app._asset_type_for(info) == app.ASSET_TYPE_LINUX_SERVER


def test_known_linux_accounts_use_linux_account_type(monkeypatch):
    monkeypatch.setattr(app, "hostdeck_lookup", lambda: ({}, {}))
    assets, _ = app.collect_observables({"fields": {"user": "root"}})
    assert assets == [{"asset_name": "root", "asset_type_id": app.ASSET_TYPE_LINUX_ACCOUNT,
                       "asset_description": "Linux-учётная запись из события Graylog"}]


def test_ad_and_generic_account_types_are_preserved(monkeypatch):
    monkeypatch.setattr(app, "hostdeck_lookup", lambda: ({}, {}))
    assets, _ = app.collect_observables({"fields": {"user": "ARSENTYEV\\testuser"}})
    assert assets[0]["asset_type_id"] == app.ASSET_TYPE_AD_ACCOUNT
    assets, _ = app.collect_observables({"fields": {"user": "glpi"}})
    assert assets[0]["asset_type_id"] == app.ASSET_TYPE_ACCOUNT
