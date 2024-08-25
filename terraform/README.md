# Weekly update procedure
## Initial steps (do this once)
* [Create a Github personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens), specifically a fine-grained token with access to the `eyeballvul`, `eyeballvul_data` and `eyeballvul_data_sources` repositories (permissions: read access to metadata, read and write access to code).
* Store the Github token by creating a secret in AWS Secrets Manager (use e.g. AWS's web interface).
  * make sure to be in us-east-1
  * secret type: other type of secret
  * encryption key: aws/secretsmanager
  * key: "token"
  * value: the token
  * name: "eyeballvul_github_token"
  * no rotation, no special permissions, etc
* Create an AWS IAM user named `eyeballvul_updater`
* Give it the AmazonEC2FullAccess policy
* Give it another custom policy to access the Github token secret. Click on "Add permissions", "Create inline policy", switch to the JSON editor and paste this, replacing with your AWS account ID:
```json
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": [
				"secretsmanager:GetSecretValue",
				"secretsmanager:DescribeSecret",
				"secretsmanager:GetResourcePolicy"
			],
			"Resource": "arn:aws:secretsmanager:us-east-1:ACCOUNT_ID:secret:eyeballvul_github_token-*"
		}
	]
}
```
Name the policy "github_token_access".
* Generate an access key ID and secret access key for the `eyeballvul_updater` IAM user. Store them in file `~/.aws/credentials` like so:
```
[default]
aws_access_key_id=...
aws_secret_access_key=...

```
* Install aws-cli and terraform
* Add an SSH key pair to your AWS account and to your own system, to be able to connect to the instance via SSH.
* In this directory, create a `terraform.tfvars` file containing the line:
```
key_name = "your key pair name"
```

* From this directory, run `terraform init`.

## Weekly update
Run `terraform apply`. Then once the github repositories are updated (this usually takes around an hour), run `terraform destroy`.
