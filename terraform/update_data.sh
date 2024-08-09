#!/bin/bash
set -euo pipefail

set -x

# Verify $GITHUB_TOKEN is set
if [ -z "$GITHUB_TOKEN" ]; then
  echo "GITHUB_TOKEN is not set"
  exit 1
fi
git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"
git config --global user.email "timothee.chauvin28@gmail.com"
git config --global user.name "Timothee Chauvin"

sudo apt-get update
sudo apt-get install -y make

# NVMe storage
sudo mkfs.ext4 /dev/nvme1n1
sudo mkdir /mnt/nvme
sudo mount /dev/nvme1n1 /mnt/nvme
cd /mnt/nvme
sudo chown -R ubuntu:ubuntu .

# Docker
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Make docker containers live in NVMe storage
sudo systemctl stop docker
sudo mv /var/lib/docker /mnt/nvme/docker
sudo ln -s /mnt/nvme/docker /var/lib/docker
sudo systemctl daemon-reload
sudo systemctl start docker

git clone https://github.com/timothee-chauvin/eyeballvul.git
git clone https://github.com/timothee-chauvin/eyeballvul_data.git
git clone https://github.com/timothee-chauvin/eyeballvul_data_sources.git
mkdir -p .cache/eyeballvul/repo_info
cp -r eyeballvul_data/data .cache/eyeballvul/
cp -r eyeballvul_data_sources/eyeballvul_build_cache.json .cache/eyeballvul/repo_info/cache.json
(cd eyeballvul && sudo make build)
sudo docker run --rm -v $(pwd)/.cache/eyeballvul:/home/evuser/.cache/eyeballvul eyeballvul bash -c "
set -euo pipefail
set -x
poetry run ev build download
# Temporary workaround to avoid issues: delete all vulns first.
rm -rf ~/.cache/eyeballvul/data/vulns
poetry run ev json_import
poetry run ev build convert_all
poetry run ev build postprocess
# Assert tests pass
rm -rf ~/.cache/eyeballvul/data && poetry run ev json_export
poetry run python -m pytest
poetry run python -c 'from eyeballvul import get_vulns; print(f\"{len(get_vulns()):,}\")' > ~/.cache/eyeballvul/n_vulns
poetry run python -c 'from eyeballvul import get_revisions; print(f\"{len(get_revisions()):,}\")' > ~/.cache/eyeballvul/n_revisions
poetry run python -c 'from eyeballvul import get_projects; print(f\"{len(get_projects()):,}\")' > ~/.cache/eyeballvul/n_projects
"

DATE=$(date '+%Y-%m-%d')

# eyeballvul_data
cd eyeballvul_data
rm -rf data/vulns data/revisions
cp -r /mnt/nvme/.cache/eyeballvul/data .
cat <<EOF > data/info.json
{
  "date": "$DATE"
}
EOF
git add .
git commit -m "$DATE"
git tag -a "$DATE" -m "$DATE"
git push --follow-tags

# eyeballvul_data_sources
cd ../eyeballvul_data_sources
cp /mnt/nvme/.cache/eyeballvul/repo_info/cache.json eyeballvul_build_cache.json
rm -rf osv_data/*
cp -r /mnt/nvme/.cache/eyeballvul/osv/* osv_data
git add .
git commit -m "$DATE" --allow-empty
git push

# eyeballvul
cd ../eyeballvul
n_vulns=$(cat /mnt/nvme/.cache/eyeballvul/n_vulns)
n_revisions=$(cat /mnt/nvme/.cache/eyeballvul/n_revisions)
n_projects=$(cat /mnt/nvme/.cache/eyeballvul/n_projects)
sed -i "s/eyeballvul currently contains.*/eyeballvul currently contains $n_vulns vulnerabilities, in $n_revisions revisions and $n_projects repositories (last updated $DATE)./" README.md
git add README.md
git commit -m "update stats with new data ($DATE)"
git push
