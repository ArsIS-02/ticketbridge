#!/usr/bin/env python3
"""Generate the reviewed dry-run registry from a private Graylog inventory.

The input is never copied to the output. Graylog queries, streams, field values,
hostnames and client data are deliberately excluded from the generated registry.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path


def artifact(name, builder="empty"):
    return {"name": name, "parameter_builder": builder}


def playbook(platform, artifacts, window=900):
    return {
        "platform": platform,
        "mode": "manual",
        "timeout_seconds": 300,
        "row_limit": 10000,
        "time_window_seconds": window,
        "artifacts": [artifact(*item) if isinstance(item, tuple) else artifact(item)
                      for item in artifacts],
    }


INFO = "Generic.Client.Info"
PSLIST = "Linux.Sys.Pslist"  # Canonical name; its declared alias is MacOS.Sys.Pslist.

PLAYBOOKS = {
    "linux_process": playbook("linux", [
        INFO, (PSLIST, "linux_pslist"),
        ("Linux.Network.NetstatEnriched", "linux_netstat"),
    ]),
    "linux_auth": playbook("linux", [
        INFO, (PSLIST, "linux_pslist"),
        ("Linux.Sys.LastUserLogin", "linux_last_logins"),
        ("Linux.Network.NetstatEnriched", "linux_netstat"),
    ]),
    "linux_accounts": playbook("linux", [
        INFO, "Linux.Sys.Users", "Linux.Sys.Groups",
        ("Linux.Sys.LastUserLogin", "linux_last_logins"),
    ]),
    "linux_persistence": playbook("linux", [
        INFO, (PSLIST, "linux_pslist"), "Linux.Sys.Services", "Linux.Sys.Crontab",
        ("Linux.Ssh.AuthorizedKeys", "linux_authorized_keys"),
    ]),
    "linux_system": playbook("linux", [
        INFO, "Linux.Sys.Services", "Linux.Proc.Modules", "Generic.System.HostsFile",
    ]),
    "linux_history": playbook("linux", [
        INFO, (PSLIST, "linux_pslist"), ("Linux.Sys.BashHistory", "linux_bash_history"),
    ]),
    "linux_containers": playbook("linux", [
        INFO, (PSLIST, "linux_pslist"), "Linux.Applications.Docker.Info",
    ]),
    "linux_suid": playbook("linux", [
        INFO, (PSLIST, "linux_pslist"), "Linux.Sys.SUID",
    ]),
    "linux_packages": playbook("linux", [
        INFO, "Linux.RHEL.Packages", "Linux.Debian.Packages", "Linux.SuSE.Packages",
    ]),
    "darwin_process": playbook("darwin", [
        INFO, (PSLIST, "linux_pslist"), ("MacOS.Network.Netstat", "darwin_netstat"),
    ]),
    "darwin_auth": playbook("darwin", [
        INFO, (PSLIST, "linux_pslist"), "MacOS.System.Users",
        ("MacOS.Network.Netstat", "darwin_netstat"),
    ]),
    "darwin_accounts": playbook("darwin", [
        INFO, (PSLIST, "linux_pslist"), "MacOS.System.Users",
    ]),
    "darwin_persistence": playbook("darwin", [
        INFO, (PSLIST, "linux_pslist"), "MacOS.Detection.Autoruns",
    ]),
    "darwin_security": playbook("darwin", [
        INFO, (PSLIST, "linux_pslist"), "MacOS.Detection.Autoruns", "MacOS.System.TCC",
    ]),
    "darwin_files": playbook("darwin", [
        INFO, (PSLIST, "linux_pslist"), "MacOS.System.QuarantineEvents",
        "MacOS.Applications.MRU",
    ]),
    "darwin_network": playbook("darwin", [
        INFO, (PSLIST, "linux_pslist"), ("MacOS.Network.Netstat", "darwin_netstat"),
        "Generic.System.HostsFile", "MacOS.System.Wifi",
    ]),
    "darwin_packages": playbook("darwin", [
        INFO, ("MacOS.System.Packages", "darwin_packages"),
    ]),
    "darwin_ssh_keys": playbook("darwin", [
        INFO, (PSLIST, "linux_pslist"),
        ("MacOS.Search.FileFinder", "darwin_authorized_keys"),
    ]),
    "windows_process": playbook("windows", [
        INFO, ("Windows.System.Pslist", "windows_pslist"),
        ("Windows.Network.NetstatEnriched", "windows_netstat"),
    ]),
    "windows_auth": playbook("windows", [
        INFO, ("Windows.System.Pslist", "windows_pslist"), "Windows.Sys.Users",
        "Windows.System.LocalAdmins", ("Windows.EventLogs.ExplicitLogon", "windows_explicit_logon"),
    ]),
    "windows_security_events": playbook("windows", [
        INFO, ("Windows.EventLogs.Evtx", "windows_security_evtx"),
        "Windows.System.LocalAdmins",
    ]),
    "windows_accounts": playbook("windows", [
        INFO, ("Windows.System.Pslist", "windows_pslist"), "Windows.Sys.Users",
        "Windows.System.LocalAdmins",
    ]),
    "windows_persistence": playbook("windows", [
        INFO, ("Windows.System.Pslist", "windows_pslist"),
        ("Windows.Sys.StartupItems", "windows_startup"),
        ("Windows.System.Services", "windows_services"),
        ("Windows.System.TaskScheduler", "windows_tasks"),
    ]),
    "windows_security": playbook("windows", [
        INFO, "Windows.System.CriticalServices", "Windows.System.AuditPolicy",
        "Windows.Sys.FirewallRules", ("Windows.System.Services", "windows_services"),
    ]),
    "windows_eventlogs": playbook("windows", [
        INFO, ("Windows.EventLogs.Modifications", "windows_log_modifications"),
        ("Windows.EventLogs.Cleared", "windows_cleared_logs"),
        ("Windows.System.Services", "windows_services"),
    ]),
    "windows_powershell": playbook("windows", [
        INFO, ("Windows.System.Pslist", "windows_pslist"),
        ("Windows.EventLogs.PowershellScriptblock", "windows_ps_scriptblock"),
        ("Windows.EventLogs.PowershellModule", "windows_ps_module"),
    ]),
    "windows_lateral": playbook("windows", [
        INFO, ("Windows.System.Pslist", "windows_pslist"),
        ("Windows.Network.NetstatEnriched", "windows_netstat"),
        ("Windows.EventLogs.ExplicitLogon", "windows_explicit_logon"),
        ("Windows.EventLogs.RDPAuth", "windows_rdp_auth"),
    ]),
    "windows_files": playbook("windows", [
        INFO, ("Windows.System.Pslist", "windows_pslist"),
        "Windows.Analysis.EvidenceOfDownload",
        ("Windows.Registry.RecentDocs", "windows_recent_docs"),
        ("Windows.Forensics.Prefetch", "windows_prefetch"),
    ]),
    "windows_wmi": playbook("windows", [
        INFO, ("Windows.System.Pslist", "windows_pslist"),
        "Windows.Persistence.PermanentWMIEvents",
    ]),
    "windows_credentials": playbook("windows", [
        INFO, ("Windows.System.Pslist", "windows_pslist"),
        "Windows.Detection.Impersonation", "Windows.Registry.WDigest",
    ]),
    "windows_network": playbook("windows", [
        INFO, ("Windows.System.Pslist", "windows_pslist"),
        ("Windows.Network.NetstatEnriched", "windows_netstat"),
        "Windows.System.DNSCache", "Windows.System.HostsFile",
    ]),
    "windows_tasks": playbook("windows", [
        INFO, ("Windows.System.Pslist", "windows_pslist"),
        ("Windows.System.TaskScheduler", "windows_tasks"),
        ("Windows.EventLogs.ScheduledTasks", "windows_task_events"),
    ]),
    "windows_services": playbook("windows", [
        INFO, ("Windows.System.Pslist", "windows_pslist"),
        ("Windows.System.Services", "windows_services"),
        "Windows.EventLogs.ServiceCreationComspec",
    ]),
}


def _has(title, *needles):
    return any(needle.casefold() in title.casefold() for needle in needles)


def _linux(title):
    if _has(title, "authorized_keys", "cron", "systemctl enable", "systemd-юнит",
            "закрепление"):
        return "linux_persistence"
    if _has(title, "setuid", "setgid", "прав доступа"):
        return "linux_suid"
    if _has(title, "истори", "затирание"):
        return "linux_history"
    if _has(title, "пользователя", "учётн", "групп", "/etc/passwd"):
        return "linux_accounts"
    if _has(title, "модул", "firewall", "сетевых настроек", "/etc/hosts",
            "sshd_config", "системного времени", "selinux", "остановка службы",
            "остановка auditd", "отключение аудита"):
        return "linux_system"
    if _has(title, "контейнер", "docker"):
        return "linux_containers"
    if _has(title, "ssh", "sudo", "подбор пароля", "успешный вход"):
        return "linux_auth"
    return "linux_process"


def _freeipa(title):
    if _has(title, "остановка служб", "certmonger"):
        return "linux_system"
    if _has(title, "пользовател", "групп", "hbac", "sudo", "политик", "ролей",
            "разблокировка", "атрибутов безопасности"):
        return "linux_accounts"
    if _has(title, "kerberos", "вход", "подбор пароля", "ldap"):
        return "linux_auth"
    return "linux_process"


def _darwin(title):
    if "authorized_keys" in title.casefold():
        return "darwin_ssh_keys"
    if _has(title, "автозагруз", "launchd", "элемент входа", "login item",
            "конфигурационного профиля", "профиля конфигурации"):
        return "darwin_persistence"
    if _has(title, "пользовател", "учётн", "групп"):
        return "darwin_accounts"
    if _has(title, "sudo", "входы по ssh"):
        return "darwin_auth"
    if _has(title, "dns", "прокси", "hosts", "tcp-порт", "wi-fi", "airdrop",
            "удалённого входа", "screen sharing", "удалённого доступа"):
        return "darwin_network"
    if _has(title, "tcc", "sip", "gatekeeper", "карантин", "сертификат",
            "межсетевого", "авторизации", "агентов сбора", "keychain", "очистка журналов"):
        return "darwin_security"
    if _has(title, "браузера", "usb", "apple-устройство", "мобильное устройство"):
        return "darwin_files"
    return "darwin_process"


def _windows(title):
    if _has(title, "powershell"):
        return "windows_powershell"
    if _has(title, "wmi"):
        return "windows_wmi"
    if _has(title, "dcsync", "kerberoasting", "kerberos", "ntlm", "4736", "5136",
            "4706/4707/4716"):
        return "windows_security_events"
    if _has(title, "задач", "планировщик"):
        return "windows_tasks"
    if _has(title, "служба", "службы", "psexec"):
        return "windows_services"
    if _has(title, "автозагрузка", "ifeo", "appinit", "winlogon"):
        return "windows_persistence"
    if _has(title, "памяти lsass", "дамп учётных"):
        return "windows_credentials"
    if _has(title, "defender", "защиты", "аудита", "firewall", "sysmon", "uac"):
        return "windows_security"
    if _has(title, "журнал"):
        return "windows_eventlogs"
    if _has(title, "rdp", "winrm"):
        return "windows_lateral"
    if _has(title, "вход", "подбор пароля", "блокировка учётной", "перебор"):
        return "windows_auth"
    if _has(title, "учётн", "пользовател", "групп", "администратор", "пароля",
            "ad:", "доверия домена"):
        return "windows_accounts"
    if _has(title, "dns", "именованные каналы", "внешнюю сеть"):
        return "windows_network"
    if _has(title, "исполняемый файл", "архивация", "шифровальщика", "теневых копий",
            "поиск паролей в файлах"):
        return "windows_files"
    return "windows_process"


def classify(rule):
    """Return one explicit collect/no_collection/needs_review decision."""
    title = rule.get("title") or ""
    prefix = title.split(" - ", 1)[0]
    if rule.get("state") != "ENABLED":
        return {"decision": "no_collection", "reason_code": "rule_disabled"}
    if not rule.get("alert"):
        return {"decision": "no_collection", "reason_code": "non_alert_informational"}
    if prefix in {"CANARY", "COWRIE", "TRAFFICLENS", "WAZUH"}:
        return {"decision": "needs_review", "reason_code": "ambiguous_endpoint_target"}
    if prefix in {"LOGATLAS", "SANDBOX"}:
        return {"decision": "needs_review", "reason_code": "external_analysis_target"}
    if prefix == "HEALTH" or title.startswith("Доступность:") or title.startswith("Контейнеры:"):
        return {"decision": "no_collection", "reason_code": "health_or_availability"}
    if prefix in {"KEENETIC", "ZABBIX"}:
        return {"decision": "no_collection", "reason_code": "network_or_external_monitor"}
    if prefix in {"HOMEREPO", "HOSTDECK", "ZASLON"}:
        return {"decision": "no_collection", "reason_code": "application_control_plane"}
    if prefix in {"DIGEST", "LABSCORE", "System notification events"}:
        return {"decision": "no_collection", "reason_code": "report_or_system_notification"}
    if prefix == "AUDIT" or prefix == "LNX":
        selected = _linux(title)
    elif prefix == "FREEIPA":
        selected = _freeipa(title)
    elif prefix == "DIFFWATCH":
        selected = ("linux_persistence" if "автозагрузки" in title else
                    "linux_packages" if "пакетов" in title else "linux_process")
    elif prefix == "macOS":
        selected = _darwin(title)
    elif prefix == "Windows":
        selected = _windows(title)
    else:
        raise ValueError(f"Unclassified enabled alert rule: {rule.get('id')} {prefix}")
    return {"decision": "collect", "playbook": selected, "title": title}


def generate(rules, snapshot_date):
    mappings = {}
    for rule in sorted(rules, key=lambda item: item.get("id") or ""):
        rule_id = str(rule.get("id") or "")
        if not rule_id:
            raise ValueError("Rule without id")
        mappings[rule_id] = {
            "state": rule.get("state"),
            "alert": bool(rule.get("alert")),
            **classify(rule),
        }
    installed = sorted({item["name"] for pb in PLAYBOOKS.values() for item in pb["artifacts"]})
    return {
        "schema_version": 1,
        "status": "dry_run_only",
        "max_client_age_seconds": 900,
        "coverage": {
            "inventory_snapshot": snapshot_date,
            "total_rules": len(mappings),
            "enabled_alert_rules": sum(
                item["state"] == "ENABLED" and item["alert"] for item in mappings.values()),
        },
        "installed_artifacts": installed,
        "playbooks": PLAYBOOKS,
        "rules": mappings,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("inventory", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--snapshot-date", required=True)
    parser.add_argument("--artifact-metadata", type=Path,
                        help="Private local metadata summary; only parameter names are exported")
    args = parser.parse_args()
    data = json.loads(args.inventory.read_text(encoding="utf-8"))
    rules = data.get("event_definitions", data) if isinstance(data, dict) else data
    result = generate(rules, args.snapshot_date)
    if args.artifact_metadata:
        metadata = json.loads(args.artifact_metadata.read_text(encoding="utf-8"))
        result["artifact_schemas"] = {
            name: sorted({entry.get("name") for entry in metadata[name]["parameters"]
                          if entry.get("name")})
            for name in result["installed_artifacts"]
        }
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    counts = Counter((item["decision"], item.get("playbook") or item["reason_code"])
                     for item in result["rules"].values())
    print("RULES", len(result["rules"]), "PLAYBOOKS", len(PLAYBOOKS),
          "ARTIFACTS", len(result["installed_artifacts"]))
    for key, count in sorted(counts.items()):
        print(*key, count)


if __name__ == "__main__":
    main()
