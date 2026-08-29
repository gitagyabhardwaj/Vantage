# ⚠️ WARNING: This file is intentionally vulnerable for demo purposes.

# RULE AWS-001: Public S3 bucket — CRITICAL
resource "aws_s3_bucket" "data_lake" {
  bucket = "company-sensitive-data-lake"
  acl    = "public-read"
}

# RULE AWS-002: SSH open to the world — CRITICAL
resource "aws_security_group" "web_sg" {
  name = "web-security-group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# RULE AWS-003: IAM star/star permissions — HIGH
resource "aws_iam_policy" "overpowered_policy" {
  name = "OverpoweredPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# RULE AWS-004: Unencrypted RDS — HIGH
resource "aws_db_instance" "main_db" {
  identifier        = "production-db"
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  storage_encrypted = false
}

# RULE AWS-005: Versioning suspended — MEDIUM
resource "aws_s3_bucket_versioning" "data_lake_versioning" {
  bucket = aws_s3_bucket.data_lake.id
  versioning_configuration {
    status = "Suspended"
  }
}

# RULE AWS-006: EC2 Public IP — HIGH
resource "aws_instance" "web_server" {
  ami                         = "ami-123456"
  instance_type               = "t2.micro"
  associate_public_ip_address = true
}

# RULE AWS-007: RDP Open to World — CRITICAL
resource "aws_security_group" "windows_sg" {
  name = "windows-sg"
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# RULE AWS-008: EBS Unencrypted — HIGH
resource "aws_ebs_volume" "data_drive" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted         = false
}

# RULE AWS-009: ECR Image Scanning Disabled — MEDIUM
resource "aws_ecr_repository" "app_repo" {
  name = "my-app-repo"
  image_scanning_configuration {
    scan_on_push = false
  }
}

# RULE AWS-010: SQS Unencrypted — HIGH
resource "aws_sqs_queue" "message_queue" {
  name = "my-message-queue"
  sqs_managed_sse_enabled = false
}
