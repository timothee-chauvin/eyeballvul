# Weekly update

Runs unattended every Friday 05:00 UTC via the `weekly update` GitHub Actions workflow:
it launches a self-terminating EC2 instance that builds the data, pushes to the three
repositories, and shuts itself down (success or failure). On failure, the instance files
a `weekly update failed` issue on this repo with the log tail, and the workflow run goes
red (GitHub emails on that).

Manual run: `gh workflow run "weekly update"` (or the Actions tab). To rehearse without
pushing any data (e.g. after changing the pipeline): `gh workflow run "weekly update" -f dry_run=true`.

To debug a run: find the instance IP in the AWS console or with
`aws ec2 describe-instances --filters Name=tag:Name,Values=eyeballvul_updater`, then
`ssh ubuntu@<ip>` (key pair `eyeballvul_aws`) and `tail -f /var/log/update_data.log`.

## Initial setup (once)

1. [Create a Github personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens):
   a fine-grained token with access to the `eyeballvul`, `eyeballvul_data` and
   `eyeballvul_data_sources` repositories. Permissions: read on metadata, read/write on
   code, read/write on issues (used for failure reports). Fine-grained tokens expire
   after at most one year: set a reminder to rotate it.
2. Store it as an Actions secret on this repo: `gh secret set EYEBALLVUL_UPDATE_PAT`
   (paste the token when prompted).
3. Create an access key for an IAM user with IAM + EC2 permissions (needed once, to
   create the role that the workflow assumes). In the AWS console, signed in as root or
   an existing admin:
   * IAM > Users > Create user. Name it e.g. `admin`; leave console access unchecked.
   * Permissions: "Attach policies directly" > `IAMFullAccess` + `AmazonEC2FullAccess`
     (or `AdministratorAccess`). Create the user.
   * Open the user > Security credentials > Access keys > Create access key > use case
     "Command Line Interface (CLI)" > confirm > next. Description tag value:
     `admin terraform applies from laptop` (so a later key audit shows where it lives
     and what it's for) > create.
   * Copy both values immediately (the secret is shown only once) into
     `~/.aws/credentials`:
   ```
   [admin]
   aws_access_key_id=AKIA...
   aws_secret_access_key=...
   ```
4. From the repository root, run:
   ```
   AWS_PROFILE=admin terraform -chdir=terraform init
   AWS_PROFILE=admin terraform -chdir=terraform apply
   ```
   This creates the durable infrastructure (4 resources): the `allow_ssh` security
   group, the GitHub OIDC identity provider, and the `gha_eyeballvul_updater` IAM role
   (+ its inline policy) that the workflow assumes — scoped to launching, describing
   and terminating EC2 instances. No long-lived AWS keys are stored in GitHub.
5. Add an SSH key pair named `eyeballvul_aws` to the AWS account (used only for
   debugging): `aws ec2 import-key-pair --key-name eyeballvul_aws --public-key-material fileb://$HOME/.ssh/id_ed25519_eyeballvul_aws.pub`

## Design notes

The ephemeral instance is launched by `.github/scripts/launch_update.sh`, not by
terraform: it terminates itself out-of-band (user_data ends in `shutdown -h now` with
`--instance-initiated-shutdown-behavior terminate`), which terraform state handles
poorly. The pipeline logic lives in `terraform/update_data.sh`, shared by any launch
path; `.github/scripts/render_user_data.py` wraps it with the failure-report trap and
the token.
