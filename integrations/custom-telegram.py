#!/var/ossec/framework/python/bin/python3
"""
custom-telegram.py — Wazuh integratord script to send alert notifications to a Telegram chat.

Wazuh calls integrations with three positional args:
  argv[1] = path to a temp file containing the single alert JSON
  argv[2] = api_key (from ossec.conf <api_key>) -> here we abuse this field to pass BOT_TOKEN
  argv[3] = hook_url (from ossec.conf <hook_url>) -> not used for auth, Telegram URL is built from BOT_TOKEN

We hardcode CHAT_ID here since Wazuh integration blocks only give us 2 free string slots
(api_key, hook_url) and we need three values (token, chat_id, and nothing else). If you'd rather
keep values out of the script, you can instead pass "TOKEN|CHAT_ID" as the api_key field and split on "|".
"""

import sys
import json
import os
import ssl
import urllib.request
import urllib.error

# ---- Config ----
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "REPLACE_WITH_CHAT_ID")
# ----------------

def send_telegram(bot_token, chat_id, text):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = json.dumps({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    # NOTE: cert verification disabled here as a time-boxed workaround for a
    # missing CA root (GoDaddy G2) in this container's trust store — see
    # project README for details. Fix properly (update ca-certificates in
    # the image) before reusing this in a non-lab environment.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            body = resp.read().decode("utf-8")
            sys.stderr.write(f"Telegram response: {resp.status} {body}\n")
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"Telegram HTTPError: {e.code} {e.read().decode('utf-8', 'ignore')}\n")
    except Exception as e:
        sys.stderr.write(f"Telegram send failed: {e}\n")


def build_message(alert):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    rule_id = str(rule.get("id", "unknown"))
    level = rule.get("level", "?")
    description = rule.get("description", "No description")
    agent_name = agent.get("name", "unknown")
    agent_ip = agent.get("ip", "unknown")

    # Try to pull a bit of context depending on alert source (Falco vs Windows vs generic)
    data = alert.get("data", {})
    context_line = ""
    if rule_id.startswith("1002"):  # Falco rules in this deployment
        output_fields = data.get("output_fields", {})
        pod = output_fields.get("k8s.pod.name", "unknown")
        proc = output_fields.get("proc.name", "unknown")
        context_line = f"Pod: `{pod}`\nProcess: `{proc}`"
    elif "win" in data:
        eventdata = data.get("win", {}).get("eventdata", {})
        target = eventdata.get("targetUserName", "unknown")
        context_line = f"Target account: `{target}`"

    severity_icon = "🔴" if int(level) >= 10 else ("🟠" if int(level) >= 7 else "🟡")

    text = (
        f"{severity_icon} *New Wazuh Alert*\n"
        f"Rule: `{rule_id}` (level {level})\n"
        f"{description}\n"
        f"Agent: `{agent_name}` ({agent_ip})\n"
    )
    if context_line:
        text += f"{context_line}\n"
    return text


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("Usage: custom-telegram.py <alert_file> <bot_token> [unused_hook_url]\n")
        sys.exit(1)

    alert_file = sys.argv[1]
    bot_token = sys.argv[2]

    with open(alert_file, "r") as f:
        alert = json.load(f)

    text = build_message(alert)
    send_telegram(bot_token, CHAT_ID, text)


if __name__ == "__main__":
    main()
