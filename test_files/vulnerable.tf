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
