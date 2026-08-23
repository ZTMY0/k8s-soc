#!/usr/bin/env python3
import sys
import json
import os
import requests

CORTEX_URL = os.environ.get("CORTEX_URL", "http://cortex:9001")
CORTEX_API_KEY = os.environ.get("CORTEX_API_KEY")

# Known attacker workstation IP in the lab (Kali WSL). Windows security events
# (4720/4722/4732/etc.) don't carry a remote source IP, so for our custom
# compromise-chain rules we attach this known attacker IP ourselves. This is
# lab-specific - in a real deployment this would come from network telemetry
# (e.g. correlating with a firewall/EDR log), not a hardcoded constant.
KNOWN_ATTACKER_IP = os.environ.get("KNOWN_ATTACKER_IP", "0.0.0.0")

# Human-readable short titles for our custom high-value rules.
# Anything not in this map falls back to the raw Wazuh description, so
# nothing breaks when new rules are added.
RULE_TITLES = {
    "100100": "Kerberos service ticket requested",
    "100101": "Possible Kerberoasting attempt",
    "100102": "Kerberos ticket enumeration/abuse",
    "100103": "Privileged account NTLM logon",
    "100104": "Backdoor account created by compromised identity",
    "100105": "Privilege escalation: compromised account modified Administrators group",
    "100106": "CONFIRMED COMPROMISE CHAIN: backdoor account created and escalated to admin",
}

# Rules that represent a confirmed, high-confidence compromise (not just a
# single suspicious event) get auto-case-promotion tag + top severity.
CONFIRMED_COMPROMISE_RULES = {"100106"}


def severity_for_level(level, rule_id):
    """Map Wazuh rule level -> TheHive severity (1 low, 2 medium, 3 high, 4 critical)."""
    if rule_id in CONFIRMED_COMPROMISE_RULES:
        return 4
    if level >= 14:
        return 4
    if level >= 12:
        return 3
    if level >= 7:
        return 2
    return 1


def build_title(rule):
    rule_id = str(rule.get("id", ""))
    short = RULE_TITLES.get(rule_id)
    if short:
        return f"[{rule_id}] {short}"
    return f"[{rule_id}] {rule.get('description', 'Unknown Wazuh alert')}"


def main():
    alert_file = sys.argv[1]
    api_key = sys.argv[2]
    hook_url = sys.argv[3]

    with open(alert_file) as f:
        alert = json.load(f)

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    eventdata = alert.get("data", {}).get("win", {}).get("eventdata", {})

    rule_id = str(rule.get("id", ""))
    level = rule.get("level", 0)

    target = (
        eventdata.get("targetUserName")
        or eventdata.get("subjectUserName")
        or "unknown"
    )
    actor = eventdata.get("subjectUserName") or "unknown"
    source_ip = eventdata.get("ipAddress") or eventdata.get("srcip") or "unknown"

    # Windows security events for account creation/group changes don't carry
    # a remote IP. For our lab's compromise-chain rules, fall back to the
    # known attacker workstation IP so we still get an IP observable to run
    # network-focused Cortex analyzers against.
    if source_ip == "unknown" and rule_id in CONFIRMED_COMPROMISE_RULES.union({"100104", "100105"}):
        source_ip = KNOWN_ATTACKER_IP

    observables = []
    if source_ip and source_ip != "unknown":
        observables.append({
            "dataType": "ip",
            "data": source_ip,
            "message": f"Source IP for rule {rule_id}",
            "tlp": 2,
            "ioc": True,
        })
    if target and target != "unknown":
        observables.append({
            "dataType": "other",
            "data": target,
            "message": f"Target account for rule {rule_id}",
            "tlp": 2,
            "ioc": True,
        })

    tags = [
        "wazuh",
        f"agent:{agent.get('name', 'unknown')}",
        f"rule:{rule_id}",
        f"actor:{actor}",
        f"target:{target}",
    ]
    if rule_id in CONFIRMED_COMPROMISE_RULES:
        tags.append("confirmed_compromise")
        tags.append("auto_case")

    mitre_ids = rule.get("mitre", {}).get("id", []) if isinstance(rule.get("mitre"), dict) else []
    for m in mitre_ids:
        tags.append(f"mitre:{m}")

    description_lines = [
        f"**Rule**: {rule_id} (level {level})",
        f"**Agent**: {agent.get('name')} ({agent.get('ip', 'n/a')})",
        f"**Actor account**: {actor}",
        f"**Target account**: {target}",
        f"**Source IP**: {source_ip}",
    ]
    if mitre_ids:
        description_lines.append(f"**MITRE ATT&CK**: {', '.join(mitre_ids)}")
    description_lines.append("")
    description_lines.append(f"**Original Wazuh description**: {rule.get('description', 'n/a')}")

    if rule_id in CONFIRMED_COMPROMISE_RULES:
        description_lines.insert(0, "**THIS IS A CONFIRMED COMPROMISE CHAIN - immediate response recommended.**\n")

    description_lines.append("\n---\n**Raw alert (truncated)**:\n```\n" + json.dumps(alert, indent=2)[:2000] + "\n```")

    payload = {
        "title": build_title(rule),
        "description": "\n".join(description_lines),
        "type": "wazuh",
        "source": "wazuh",
        "sourceRef": f"{rule_id}_{agent.get('name','unknown')}_{target}_{alert.get('id','')}",
        "severity": severity_for_level(level, rule_id),
        "tlp": 2,
        "tags": tags,
        "status": "New",
        "observables": observables,
    }

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    resp = requests.post(hook_url, headers=headers, json=payload, verify=False)
    sys.stderr.write(f"TheHive response: {resp.status_code} {resp.text}\n")

    if resp.status_code != 201:
        return

    # Auto-create a Case for confirmed-compromise rules, no human click needed.
    # hook_url looks like http://thehive:9000/api/v1/alert -> derive the base API URL from it.
    if rule_id in CONFIRMED_COMPROMISE_RULES:
        try:
            base_url = hook_url.rsplit("/api/", 1)[0]  # e.g. http://thehive:9000
            case_payload = {
                "title": build_title(rule),
                "description": "\n".join(description_lines),
                "severity": severity_for_level(level, rule_id),
                "tlp": 2,
                "tags": tags,
                "status": "InProgress",
                # If a template exists with this name, TheHive will apply it
                # (pre-filled response tasks). If not found, TheHive just
                # ignores the field and creates a blank case - safe either way.
                "caseTemplate": "Confirmed Compromise Response",
            }
            case_resp = requests.post(
                f"{base_url}/api/v1/case",
                headers=headers,
                json=case_payload,
                verify=False,
            )
            sys.stderr.write(f"TheHive auto-case response: {case_resp.status_code} {case_resp.text}\n")

            if case_resp.status_code == 201:
                case_id = case_resp.json().get("_id")
                for obs in observables:
                    obs_resp = requests.post(
                        f"{base_url}/api/v1/case/{case_id}/observable",
                        headers=headers,
                        json=obs,
                        verify=False,
                    )
                    sys.stderr.write(f"Attached observable to case: {obs_resp.status_code}\n")
        except Exception as e:
            sys.stderr.write(f"Auto-case creation failed: {e}\n")

    cortex_headers = {
        "Authorization": f"Bearer {CORTEX_API_KEY}",
        "Content-Type": "application/json",
    }

    # For each observable, ask Cortex which enabled analyzers support that
    # exact data type, then run all of them. This avoids hardcoding analyzer
    # IDs (which change if analyzers are re-enabled/reconfigured) and avoids
    # wasting jobs running IP-only analyzers against a username, etc.
    for obs in observables:
        data_type = obs["dataType"]
        try:
            list_resp = requests.get(
                f"{CORTEX_URL}/api/analyzer/type/{data_type}",
                headers=cortex_headers,
                verify=False,
            )
            if list_resp.status_code != 200:
                sys.stderr.write(f"Cortex analyzer lookup for {data_type} failed: {list_resp.status_code} {list_resp.text}\n")
                continue

            analyzers = list_resp.json()
            sys.stderr.write(f"Found {len(analyzers)} analyzer(s) for dataType={data_type}\n")

            for analyzer in analyzers:
                analyzer_id = analyzer.get("id") or analyzer.get("_id")
                analyzer_name = analyzer.get("name", analyzer_id)
                if not analyzer_id:
                    continue
                run_payload = {
                    "data": obs["data"],
                    "dataType": data_type,
                    "tlp": 2,
                    "message": f"Auto-analysis triggered by Wazuh rule {rule_id}",
                    "parameters": {},
                }
                run_resp = requests.post(
                    f"{CORTEX_URL}/api/analyzer/{analyzer_id}/run",
                    headers=cortex_headers,
                    json=run_payload,
                    verify=False,
                )
                sys.stderr.write(f"Ran {analyzer_name} on {data_type}='{obs['data']}': {run_resp.status_code}\n")
        except Exception as e:
            sys.stderr.write(f"Cortex auto-analysis failed for dataType={data_type}: {e}\n")


if __name__ == "__main__":
    main()
