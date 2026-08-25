# Durable infrastructure for the unattended weekly update: GitHub Actions
# authenticates to AWS via OIDC (no long-lived keys) and assumes a role that
# can only launch/terminate/describe EC2 instances.
# Applying this file requires IAM permissions (admin profile), once.

data "aws_caller_identity" "current" {}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "gha_updater" {
  name = "gha_eyeballvul_updater"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike   = { "token.actions.githubusercontent.com:sub" = "repo:timothee-chauvin/eyeballvul:*" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "gha_updater" {
  name = "launch_updater_instance"
  role = aws_iam_role.gha_updater.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ec2:RunInstances",
        "ec2:CreateTags",
        "ec2:DescribeImages",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "ec2:GetConsoleOutput",
        "ec2:TerminateInstances",
      ]
      Resource = "*"
    }]
  })
}

output "gha_role_arn" {
  value = aws_iam_role.gha_updater.arn
}
