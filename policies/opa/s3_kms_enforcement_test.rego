package terraform.analysis

import rego.v1

# Positive case: S3 bucket with a matching KMS SSE configuration.
test_positive if {
    data.terraform.analysis.allow with input as {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.audit_bucket",
                "type": "aws_s3_bucket",
                "change": {"actions": ["create"]}
            },
            {
                "address": "aws_s3_bucket_server_side_encryption_configuration.audit_bucket_sse",
                "type": "aws_s3_bucket_server_side_encryption_configuration",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "rule": [
                            {
                                "apply_server_side_encryption_by_default": [
                                    {
                                        "sse_algorithm": "aws:kms",
                                        "kms_master_key_id": "arn:aws:kms:us-east-1:000000000000:key/12345678-1234-1234-1234-123456789012"
                                    }
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    }
}

# Negative case: S3 bucket with no encryption configuration.
test_negative if {
    data.terraform.analysis.deny["S3 bucket 'aws_s3_bucket.audit_bucket' must have server-side encryption (SSE) configured."] with input as {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.audit_bucket",
                "type": "aws_s3_bucket",
                "change": {"actions": ["create"]}
            }
        ]
    }
}
