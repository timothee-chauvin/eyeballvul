variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "key_name" {
  description = "Name of the SSH key pair (already present in the AWS account) to use for the instance"
  type        = string
}
