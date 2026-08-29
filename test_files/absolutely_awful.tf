# ==============================================================================
# VANTAGE "ABSOLUTELY AWFUL" INFRASTRUCTURE
# This file is intentionally designed to violate almost every security rule.
# It should generate a massive amount of Critical and High findings and 
# drop your score down to an F.
# ==============================================================================

resource "aws_s3_bucket" "disaster_bucket" {
  bucket = "company-confidential-data-public"
  acl    = "public-read-write"
}

resource "aws_s3_bucket_public_access_block" "disaster_bucket_pab" {
  bucket = aws_s3_bucket.disaster_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_security_group" "open_to_the_world" {
  name        = "allow_all"
  description = "Allows absolutely everything"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "god_mode" {
  name        = "allow_everything"
  description = "Grants admin access to anyone who assumes it"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_db_instance" "leaky_db" {
  engine               = "postgres"
  instance_class       = "db.m5.large"
  allocated_storage    = 500
  username             = "admin"
  password             = "password123"
  publicly_accessible  = true
  storage_encrypted    = false
  multi_az             = false
  skip_final_snapshot  = true
}

resource "aws_instance" "exposed_server" {
  ami                         = "ami-123456"
  instance_type               = "t3.large"
  associate_public_ip_address = true
  
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional" # IMDSv1 enabled (very bad)
  }
}

resource "aws_ebs_volume" "unencrypted_disk" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

resource "aws_ecr_repository" "vulnerable_registry" {
  name                 = "prod-images"
  image_tag_mutability = "MUTABLE"
  
  image_scanning_configuration {
    scan_on_push = false
  }
}

resource "aws_cloudtrail" "weak_trail" {
  name                          = "company-trail"
  s3_bucket_name                = aws_s3_bucket.disaster_bucket.id
  is_multi_region_trail         = false
  enable_log_file_validation    = false
}

resource "aws_kms_key" "forgotten_key" {
  description             = "KMS key with no rotation"
  enable_key_rotation     = false
}

resource "aws_eks_cluster" "public_cluster" {
  name     = "prod-cluster"
  role_arn = aws_iam_role.eks_role.arn

  vpc_config {
    endpoint_public_access  = true
    endpoint_private_access = false
  }
}

resource "aws_cloudfront_distribution" "insecure_cdn" {
  enabled             = true
  
  default_cache_behavior {
    viewer_protocol_policy = "allow-all" # Allows HTTP
  }
  
  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1" # Deprecated TLS version
  }
}

resource "aws_efs_file_system" "shared_drive" {
  encrypted = false
}

resource "aws_sqs_queue" "plaintext_queue" {
  name = "sensitive-messages"
  # Missing kms_master_key_id, meaning it's unencrypted
}

resource "aws_sns_topic" "plaintext_topic" {
  name = "sensitive-notifications"
  # Missing kms_master_key_id
}

resource "aws_redshift_cluster" "data_warehouse" {
  cluster_identifier  = "prod-dw"
  node_type           = "dc2.large"
  publicly_accessible = true
  encrypted           = false
}
