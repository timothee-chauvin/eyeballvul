#!/usr/bin/env python3
"""Email the start/outcome of a weekly update run via Gmail SMTP.

Usage: notify.py start | notify.py finish STATUS START_TIME
Mirrors the old pve cron wrapper; GitHub itself never notifies the account
whose PAT filed the failure issue, so the email is the only signal that reaches a human.
"""
import json
import os
import smtplib
import sys
import urllib.request
from datetime import UTC, datetime
from email.message import EmailMessage

REPO = "timothee-chauvin/eyeballvul"
RUN_URL = f"https://github.com/{REPO}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
PREFIX = "[eyeballvul-update]" + (" DRY RUN" if os.environ.get("DRY_RUN") == "true" else "")


def send(subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = os.environ["GMAIL_USER"]
    msg["To"] = os.environ["NOTIFY_EMAIL"]
    msg.set_content(body)
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
        s.login(os.environ["GMAIL_USER"], os.environ["GMAIL_APP_PASSWORD"])
        s.send_message(msg)


def failure_issue_url(since: str) -> str | None:
    req = urllib.request.Request(
        f"https://api.github.com/repos/{REPO}/issues?state=all&since={since}",
        headers={"Authorization": f"Bearer {os.environ['GH_TOKEN']}"},
    )
    issues = json.load(urllib.request.urlopen(req))  # nosec B310: fixed https URL
    return next(
        (i["html_url"] for i in issues if i["title"].startswith("weekly update failed")), None
    )


def main(cmd: str, *args: str) -> None:
    now = datetime.now(UTC)
    if cmd == "start":
        send(f"{PREFIX} starting", f"Started: {now.isoformat()}\nRun: {RUN_URL}\n")
        return
    status, start = args
    lines = [f"Status: {status}", f"Run: {RUN_URL}"]
    subject = f"{PREFIX} {status}"
    if start:
        minutes = (now - datetime.fromisoformat(start)).total_seconds() / 60
        subject += f" ({minutes:.0f} min)"
        lines += [f"Started: {start}", f"Duration: {minutes:.0f} min"]
        if issue := failure_issue_url(start):
            lines.append(f"Failure issue: {issue}")
    if status == "cancelled":
        lines.append("Job hit its time cap; the instance may still finish and push on its own.")
    send(subject, "\n".join(lines) + "\n")


if __name__ == "__main__":
    main(*sys.argv[1:])
