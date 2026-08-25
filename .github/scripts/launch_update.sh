#!/bin/bash
# Launch a self-terminating updater instance. Expects $GH_PAT and AWS credentials.
set -euo pipefail

AMI=$(aws ec2 describe-images --owners 099720109477 \
  --filters 'Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-*-*-arm64-server-*' 'Name=architecture,Values=arm64' \
  --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)
SG=$(aws ec2 describe-security-groups --group-names allow_ssh \
  --query 'SecurityGroups[0].GroupId' --output text)

python3 .github/scripts/render_user_data.py > /tmp/user_data.sh

IID=$(aws ec2 run-instances \
  --image-id "$AMI" \
  --instance-type m8gd.2xlarge \
  --key-name eyeballvul_aws \
  --security-group-ids "$SG" \
  --user-data file:///tmp/user_data.sh \
  --instance-initiated-shutdown-behavior terminate \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=eyeballvul_updater}]' \
  --query 'Instances[0].InstanceId' --output text)
rm /tmp/user_data.sh

echo "Launched $IID (AMI $AMI)"
echo "instance_id=$IID" >> "$GITHUB_OUTPUT"
echo "start_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$GITHUB_OUTPUT"
