#!/usr/bin/env python3
"""Render the EC2 user_data for an unattended weekly update run.

Reads the GitHub PAT from $GH_PAT and the pipeline script from
terraform/update_data.sh; prints the full user_data script to stdout.
The instance reports failures as a GitHub issue and always shuts itself
down; it must be launched with --instance-initiated-shutdown-behavior
terminate so that shutdown means termination.
"""
import os
import pathlib

pat = os.environ["GH_PAT"]
script = pathlib.Path("terraform/update_data.sh").read_text()

user_data = """#!/bin/bash
set -euo pipefail
LOG_FILE="/var/log/update_data.log"
exec > >(tee -a "$LOG_FILE") 2>&1

export GITHUB_TOKEN=__PAT__

cat > /opt/report_failure.py <<'PYEOF'
import datetime
import json
import os
import urllib.request

log = open("/var/log/update_data.log", errors="replace").read()[-6000:]
date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
body = (
    "The unattended weekly update failed. "
    "Last 6000 bytes of /var/log/update_data.log:\\n\\n```\\n" + log + "\\n```"
)
req = urllib.request.Request(
    "https://api.github.com/repos/timothee-chauvin/eyeballvul/issues",
    data=json.dumps({"title": f"weekly update failed ({date})", "body": body}).encode(),
    headers={
        "Authorization": "Bearer " + os.environ["GITHUB_TOKEN"],
        "Accept": "application/vnd.github+json",
    },
)
print(urllib.request.urlopen(req).status)
PYEOF

STATUS=failure
finish() {
  if [ "$STATUS" != success ]; then
    python3 /opt/report_failure.py || true
  fi
  shutdown -h now
}
trap finish EXIT

su - ubuntu <<'EOSU'
export GITHUB_TOKEN=__PAT__
__DRY__
__SCRIPT__
EOSU

STATUS=success
"""

dry = os.environ.get("DRY_RUN", "").lower() in ("1", "true")
dry_line = "export EV_DRY_RUN=1" if dry else ":"
print(user_data.replace("__PAT__", pat).replace("__DRY__", dry_line).replace("__SCRIPT__", script))
