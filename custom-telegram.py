#!/var/ossec/venv/bin/python

import json
import re
import sys
from datetime import datetime

import requests

# Telegram Bot credentials
bot_token = ""  # Replace with your Telegram bot token
chat_id = ""  # Replace with your Telegram chat ID

# === Excluded Wazuh Rule IDs ===
excluded_rules: list = []  # Example: ["1002", "5715", "18107"]


def escape_markdown_v2(text):
    if not isinstance(text, str):
        text = str(text)
    # Escape special MarkdownV2 characters
    escape_chars = r"_*[]()~`>#+-=|{}.!"
    return re.sub(r"([%s])" % re.escape(escape_chars), r"\\\1", text)


def main():
    if len(sys.argv) < 2:
        print("[ERROR] No alert file path provided.")
        sys.exit(1)

    alert_file = sys.argv[1]

    try:
        with open(alert_file, "r") as f:
            alert = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to read or parse alert JSON file: {e}")
        sys.exit(1)

    rule_id = alert.get("rule", {}).get("id", None)

    if rule_id in excluded_rules:
        print(f"[INFO] Skipping excluded rule ID: {rule_id}")
        sys.exit(0)

    # Extract fields
    data = alert.get("data", {})
    srcuser = data.get("srcuser") or data.get("dstuser") or "unknown"
    srcport = data.get("srcport", "unknown")
    srcip = alert.get("data", {}).get("srcip", "unknown")
    agent_name = alert.get("agent", {}).get("name", "unknown")
    alert_level = alert.get("rule", {}).get("level", "unknown")
    rule_id = alert.get("rule", {}).get("id", "unknown")
    description = alert.get("rule", {}).get("description", "No description")
    full_log = alert.get("full_log", "No full log available")
    timestamp_raw = alert.get("timestamp", "unknown")

    # Convert timestamp to human readable format (date and time to seconds)
    try:
        # Try parsing ISO8601 format
        dt = datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00"))
        timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        timestamp = timestamp_raw  # fallback if parsing fails

    # Build message
    message = (
        "*🚨 Wazuh Alert Notification*\n\n"
        f"🕒 *Time:* `{escape_markdown_v2(timestamp)}`\n"
        f"👤 *Username:* `{escape_markdown_v2(srcuser)}`\n"
        f"🌐 *Source IP:* `{escape_markdown_v2(srcip)}`\n"
        f"🚪 *Source Port:* `{escape_markdown_v2(srcport)}`\n"
        f"💻 *Agent:* {escape_markdown_v2(agent_name)}\n\n"
        f"🆔 *Rule ID:* `{escape_markdown_v2(rule_id)}`\n"
        f"🧱 *Level:* *{escape_markdown_v2(alert_level)}*\n\n"
        f"📄 *Description:*\n{escape_markdown_v2(description)}\n\n"
        f"🔍 *Full Log:*\n{escape_markdown_v2(full_log)}"
    )

    vuln = alert.get("vulnerability", {})
    cve_id = vuln.get("cve", "")
    cve_title = vuln.get("title", "")
    cve_url = f"https://cti.wazuh.com/vulnerabilities/cves/{cve_id}" if cve_id else ""

    if cve_id:
        message += (
            f"\n\n*🛡️ CVE:* `{escape_markdown_v2(cve_id)}`\n"
            f"*📄 Details:* {escape_markdown_v2(cve_title)}\n"
            f"[🔗 View in CTI]({escape_markdown_v2(cve_url)})"
        )

    # Send to Telegram
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {"chat_id": chat_id, "text": message, "parse_mode": "MarkdownV2"}

    response = requests.post(url, json=payload)
    if response.status_code != 200:
        print(f"[ERROR] Telegram response: {response.status_code} - {response.text}")


if __name__ == "__main__":
    main()
