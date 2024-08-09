# Retrieve the eyeballvul_github_token stored in AWS Secrets Manager.

data "aws_secretsmanager_secret" "github_token" {
  name = "eyeballvul_github_token"
}

data "aws_secretsmanager_secret_version" "github_token" {
  secret_id = data.aws_secretsmanager_secret.github_token.id
}

locals {
  github_token = jsondecode(data.aws_secretsmanager_secret_version.github_token.secret_string)["token"]
}
