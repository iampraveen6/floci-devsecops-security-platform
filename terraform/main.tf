# Hardened Terraform Configuration for Floci DevSecOps Platform

# 1. Customer-Managed KMS Key with Key Rotation
resource "aws_kms_key" "devsecops_key" {
  description         = "Customer-managed KMS key for DevSecOps platform encryption"
  enable_key_rotation = true
  policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Sid       = "EnableIAMUserPermissions",
        Effect    = "Allow",
        Principal = {
          # In Floci/LocalStack, the account ID is 000000000000
          AWS = "arn:aws:iam::000000000000:root"
        },
        Action    = "kms:*",
        Resource  = "*"
      }
    ]
  })

  tags = {
    Name = "devsecops-cmk"
  }
}

# 2. S3 Audit Bucket with Object Lock and Default-Deny Policy
# Note: CKV_AWS_144, CKV2_AWS_61, CKV2_AWS_62 are skipped as replication, lifecycle, and event notifications are not critical for this local-only audit bucket.
resource "aws_s3_bucket" "audit_bucket" {
  # Bucket names must be unique. Add a random suffix for local testing.
  bucket = "floci-devsecops-audit-logs"

  # CKV_AWS_18: Ensure the S3 bucket has access logging enabled
  # CKV_AWS_144: Ensure that S3 bucket has cross-region replication enabled
  # CKV2_AWS_61: Ensure that an S3 bucket has a lifecycle configuration
  # CKV2_AWS_62: Ensure S3 buckets should have event notifications enabled
  # checkov:skip=CKV_AWS_144:Cross-region replication is not required for this local-only, non-critical bucket.
  # checkov:skip=CKV2_AWS_61:A lifecycle policy is not required for this local-only, non-critical bucket.
  # checkov:skip=CKV2_AWS_62:Event notifications are not required for this local-only, non-critical bucket.
}

resource "aws_s3_bucket" "log_bucket" {
  bucket = "floci-devsecops-access-logs"
}

resource "aws_s3_bucket_public_access_block" "log_bucket_pab" {
  bucket                  = aws_s3_bucket.log_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_bucket_sse" {
  bucket = aws_s3_bucket.log_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "AES256" # SSE-S3 is required for logging destination buckets
    }
  }
}

resource "aws_s3_bucket_logging" "audit_bucket_logging" {
  bucket = aws_s3_bucket.audit_bucket.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "log/"
}

resource "aws_s3_bucket_versioning" "audit_bucket_versioning" {
  bucket = aws_s3_bucket.audit_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit_bucket_object_lock" {
  bucket              = aws_s3_bucket.audit_bucket.id
  object_lock_enabled = "Enabled"

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365 # Lock objects for 1 year
    }
  }

  depends_on = [aws_s3_bucket_versioning.audit_bucket_versioning]
}

resource "aws_s3_bucket_public_access_block" "audit_bucket_pab" {
  bucket                  = aws_s3_bucket.audit_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_bucket_sse" {
  bucket = aws_s3_bucket.audit_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.devsecops_key.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "audit_bucket_policy" {
  bucket = aws_s3_bucket.audit_bucket.id
  policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Sid       = "DenyIncorrectEncryptionHeader",
        Effect    = "Deny",
        Principal = "*",
        Action    = "s3:PutObject",
        Resource  = "${aws_s3_bucket.audit_bucket.arn}/*",
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid       = "DenyUnencryptedObjectUploads",
        Effect    = "Deny",
        Principal = "*",
        Action    = "s3:PutObject",
        Resource  = "${aws_s3_bucket.audit_bucket.arn}/*",
        Condition = {
          Null = {
            "s3:x-amz-server-side-encryption" = "true"
          }
        }
      }
    ]
  })
}

# 3. AWS Secrets Manager Secret with Automated KMS Encryption
resource "aws_secretsmanager_secret" "database_credentials" {
  # CKV2_AWS_57: Ensure Secrets Manager secrets should have automatic rotation enabled
  # checkov:skip=CKV2_AWS_57:Automatic rotation requires a Lambda function, which is out of scope for this IaC-focused example.
  name       = "dev/database/credentials"
  kms_key_id = aws_kms_key.devsecops_key.id

  tags = {
    ManagedBy = "Terraform"
  }
}

resource "aws_secretsmanager_secret_version" "database_credentials_version" {
  secret_id = aws_secretsmanager_secret.database_credentials.id
  secret_string = jsonencode({
    username = "db_user"
    password = "super_secret_password_123!"
  })
}

# 4. IAM Least-Privilege Policy for Secret Retrieval
resource "aws_iam_policy" "secret_reader_policy" {
  name        = "SecretReaderPolicy"
  description = "Policy for read-only access to specific Secrets Manager secrets"
  policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Sid      = "AllowSecretRead",
        Effect   = "Allow",
        Action   = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ],
        Resource = aws_secretsmanager_secret.database_credentials.arn
      },
      {
        Sid      = "AllowKMSDecryptForSecret",
        Effect   = "Allow",
        Action   = "kms:Decrypt",
        Resource = aws_kms_key.devsecops_key.arn,
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.us-east-1.amazonaws.com"
          }
        }
      }
    ]
  })
}
