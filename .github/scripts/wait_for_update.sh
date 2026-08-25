#!/bin/bash
# Poll until the three repos have been pushed after $2, or the instance dies first.
# With DRY_RUN=true, success is instead: the pipeline logs the skip marker to the
# console and the instance terminates itself without filing a failure issue.
set -euo pipefail
IID=$1
START=$2
DRY_RUN=${DRY_RUN:-false}
REPOS=(eyeballvul eyeballvul_data eyeballvul_data_sources)
marker_seen=0

failure_issue_filed() {
  curl -sf -H "Authorization: Bearer $GH_TOKEN" \
    "https://api.github.com/repos/timothee-chauvin/eyeballvul/issues?state=all&since=$START" |
    jq -e 'any(.[]; .title | startswith("weekly update failed"))' > /dev/null
}

while true; do
  if [[ "$DRY_RUN" != "true" ]]; then
    done_count=0
    for repo in "${REPOS[@]}"; do
      pushed=$(curl -sf -H "Authorization: Bearer $GH_TOKEN" \
        "https://api.github.com/repos/timothee-chauvin/$repo" | jq -r .pushed_at || echo "")
      [[ -n "$pushed" && "$pushed" > "$START" ]] && done_count=$((done_count + 1))
    done
    echo "$(date -u +%H:%M) $done_count/3 repos updated"
    if [[ "$done_count" -eq 3 ]]; then
      echo "All repos updated."
      exit 0
    fi
  elif [[ "$marker_seen" -eq 0 ]] && aws ec2 get-console-output --instance-id "$IID" \
      --latest --output text 2>/dev/null | grep -q "EV_DRY_RUN set"; then
    marker_seen=1
    echo "$(date -u +%H:%M) dry-run skip marker seen in console output"
  fi
  state=$(aws ec2 describe-instances --instance-ids "$IID" \
    --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null || echo unknown)
  if [[ "$state" == "terminated" || "$state" == "stopped" ]]; then
    if [[ "$DRY_RUN" == "true" && "$marker_seen" -eq 1 ]] && ! failure_issue_filed; then
      echo "Dry run succeeded: pipeline completed, pushes skipped, instance self-terminated."
      exit 0
    fi
    echo "Instance $state before completion: the run failed."
    echo "Check the 'weekly update failed' issue on the eyeballvul repo for the log tail."
    exit 1
  fi
  [[ "$DRY_RUN" == "true" ]] && echo "$(date -u +%H:%M) instance $state"
  sleep 300
done
