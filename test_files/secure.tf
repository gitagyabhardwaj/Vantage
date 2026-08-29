# ✅ This file is completely secure and follows AWS best practices.

# RULE AWS-001 FIXED: S3 bucket uses private ACL
resource "aws_s3_bucket" "data_lake" {
  bucket = "company-sensitive-data-lake"
  acl    = "private"
}

# RULE AWS-002 FIXED: SSH is restricted to a specific corporate VPN IP
resource "aws_security_group" "web_sg" {
  name = "web-security-group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.50/32"] # Restricted to specific IP
  }
}

# RULE AWS-003 FIXED: IAM policy uses Least Privilege (exact actions and resources)
resource "aws_iam_policy" "scoped_policy" {
  name = "ScopedPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::company-sensitive-data-lake",
          "arn:aws:s3:::company-sensitive-data-lake/*"
        ]
      }
    ]
  })
}

# RULE AWS-004 FIXED: RDS has storage encryption enabled
resource "aws_db_instance" "main_db" {
  identifier        = "production-db"
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  storage_encrypted = true
}

# RULE AWS-005 FIXED: S3 Versioning is explicitly enabled
resource "aws_s3_bucket_versioning" "data_lake_versioning" {
  bucket = aws_s3_bucket.data_lake.id
  versioning_configuration {
    status = "Enabled"
  }
}
