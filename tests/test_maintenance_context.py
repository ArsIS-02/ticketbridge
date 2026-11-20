import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app as tb


NOW = 1_800_000_000
UNTIL = NOW + 3600


def event(rule="availability-1", host="server-01.example.test", priority=2):
    return {
        "id": "event-1", "event_definition_id": rule,
        "message": "Availability test", "timestamp": "2027-01-15T00:00:00Z",
        "priority": priority, "fields": {"host": host},
    }


def configure(monkeypatch, until=UNTIL, reason="Плановое обновление"):
    info = {"name": "server-01.example.test", "os": "Linux", "profile": "server",
            "maintenance_until": until, "maintenance_reason": reason}
    monkeypatch.setattr(tb, "HOSTDECK_TOKEN", "secret")
    monkeypatch.setattr(tb, "AVAILABILITY_RULES", {"availability-1": "", "fallback-1": "server-01.example.test"})
    monkeypatch.setattr(tb, "hostdeck_lookup", lambda: ({"192.0.2.10": info}, {"server-01.example.test": info}))
    monkeypatch.setitem(tb._HD_CACHE, "stale", False)
    return info


def test_active_window_enriches_only_availability_without_mutation(monkeypatch):
    configure(monkeypatch)
    original = event()
    enriched = tb.with_maintenance_context(original, now=NOW)
    assert enriched is not original
    assert original["fields"] == {"host": "server-01.example.test"}
    assert enriched["fields"]["maintenance_active"] == "true"
    assert enriched["fields"]["maintenance_until"] == str(UNTIL)
    assert enriched["fields"]["maintenance_until_iso"].endswith("Z")
    assert enriched["fields"]["maintenance_reason"] == "Плановое обновление"
    assert enriched["priority"] == original["priority"]


def test_expired_window_and_missing_host_leave_event_unchanged(monkeypatch):
    configure(monkeypatch, until=NOW - 1)
    expired = event()
    assert tb.with_maintenance_context(expired, now=NOW) is expired
    monkeypatch.setattr(tb, "hostdeck_lookup", lambda: ({}, {}))
    unknown = event()
    assert tb.with_maintenance_context(unknown, now=NOW) is unknown


def test_security_event_is_not_enriched_even_with_matching_host(monkeypatch):
    configure(monkeypatch)
    security = event(rule="security-1", priority=3)
    assert tb.with_maintenance_context(security, now=NOW) is security
    assert "maintenance_active" not in security["fields"]
    assert security["priority"] == 3


def test_fallback_host_is_used_for_silence_rule(monkeypatch):
    configure(monkeypatch)
    silence = event(rule="fallback-1")
    silence["fields"] = {}
    enriched = tb.with_maintenance_context(silence, now=NOW)
    assert tb.maintenance_is_active(enriched)


def test_agent_silent_uses_agent_name_instead_of_panel_source(monkeypatch):
    configure(monkeypatch)
    silent = event()
    silent["fields"] = {"source": "homerepo", "hr_agent_name": "server-01.example.test"}
    enriched = tb.with_maintenance_context(silent, now=NOW)
    assert tb.maintenance_is_active(enriched)


def test_hostdeck_error_disables_stale_maintenance_context(monkeypatch):
    real_lookup = tb.hostdeck_lookup
    info = configure(monkeypatch)
    monkeypatch.setattr(tb, "hostdeck_lookup", real_lookup)
    monkeypatch.setattr(tb, "HOSTDECK_TTL", 300)
    monkeypatch.setattr(tb, "HOSTDECK", "http://hostdeck.invalid")
    monkeypatch.setattr(tb, "send_gelf", lambda *args, **kwargs: None)
    tb._HD_CACHE.update(ts=0.0, by_ip={}, by_name={"server-01.example.test": info}, stale=False)
    monkeypatch.setattr(tb.urllib.request, "urlopen", lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("timeout")))
    original = event()
    assert tb.with_maintenance_context(original) is original
    assert tb._HD_CACHE["stale"] is True


def test_disabled_token_does_not_use_cached_window(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(tb, "HOSTDECK_TOKEN", "")
    original = event()
    assert tb.with_maintenance_context(original, now=NOW) is original


def test_maintenance_description_is_readable_and_escaped(monkeypatch):
    configure(monkeypatch, reason="<b>Обновление</b>")
    enriched = tb.with_maintenance_context(event(), now=NOW)
    _, content, urgency = tb.compose_ticket(enriched)
    assert "🛠 Обслуживание HostDeck" in content
    assert "Окончание:" in content
    assert "&lt;b&gt;Обновление&lt;/b&gt;" in content
    assert "<b>Обновление</b>" not in content
    assert "maintenance_until_iso</td>" not in content
    assert urgency == 3


def test_iris_payload_has_maintenance_tag_but_same_severity(tmp_path, monkeypatch):
    configure(monkeypatch)
    enriched = tb.with_maintenance_context(event(priority=3), now=NOW)
    enriched["fields"]["zabbix_event_id"] = "123456"
    enriched["fields"]["zabbix_nseverity"] = 4
    enriched["fields"]["zabbix_trigger_description"] = "HTTPS unavailable"
    monkeypatch.setattr(tb, "IRIS", "https://iris.example.test")
    monkeypatch.setattr(tb, "IRIS_KEY", "secret")
    monkeypatch.setattr(tb, "STATE_DB", str(tmp_path / "state.db"))
    monkeypatch.setattr(tb, "collect_observables", lambda event: ([], []))
    payloads = []
    monkeypatch.setattr(tb, "_post_iris", lambda payload: payloads.append(payload) or (True, "801"))
    assert tb.send_iris(enriched) == (True, "801")
    payload = payloads[0]
    assert payload["alert_severity_id"] == 5
    assert payload["alert_status_id"] == 2
    assert payload["alert_tags"] == "graylog,ticketbridge,zabbix,maintenance,hostdeck"
    assert payload["alert_source_content"]["fields"]["maintenance_reason"] == "Плановое обновление"
    assert "🛠 Обслуживание HostDeck" in payload["alert_description"]


def test_security_iris_payload_is_byte_for_byte_compatible_in_routing(monkeypatch):
    configure(monkeypatch)
    security = event(rule="security-1", priority=3)
    assert tb.with_maintenance_context(security, now=NOW) is security
    monkeypatch.setattr(tb, "IRIS_CORR", False)
    monkeypatch.setattr(tb, "IRIS", "https://iris.example.test")
    monkeypatch.setattr(tb, "IRIS_KEY", "secret")
    monkeypatch.setattr(tb, "collect_observables", lambda event: ([], []))
    payloads = []
    monkeypatch.setattr(tb, "_post_iris", lambda payload: payloads.append(payload) or (True, "802"))
    assert tb.send_iris(security) == (True, "802")
    assert payloads[0]["alert_severity_id"] == 5
    assert payloads[0]["alert_tags"] == "graylog,ticketbridge"
    assert "maintenance" not in json.dumps(payloads[0])
