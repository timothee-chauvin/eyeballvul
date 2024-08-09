provider "aws" {
  region = var.aws_region
}

data "aws_ami" "ubuntu_arm64" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-*-*-arm64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }
}

resource "aws_security_group" "allow_ssh" {
  name        = "allow_ssh"
  description = "Allow SSH inbound traffic"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_ssh"
  }
}

resource "aws_instance" "instance" {
  ami                  = data.aws_ami.ubuntu_arm64.id
  instance_type        = "m6gd.2xlarge"
  user_data = <<-EOF
  #!/bin/bash
  LOG_FILE="/var/log/update_data.log"
  exec > >(tee -a "$LOG_FILE") 2>&1
  su - ubuntu <<-'EOSU'
  export GITHUB_TOKEN="${local.github_token}"
  ${file("${path.module}/update_data.sh")}
  EOSU
  EOF
  key_name             = var.key_name
  vpc_security_group_ids = [aws_security_group.allow_ssh.id]

  tags = {
    Name = "eyeballvul_updater"
  }
}

output "instance_public_ip" {
  value       = aws_instance.instance.public_ip
  description = "The public IP address of the EC2 instance"
}
