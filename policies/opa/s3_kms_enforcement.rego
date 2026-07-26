package terraform.analysis

import rego.v1

# Helper: Collect all encryption resources and map them to their target bucket reference
bucket_encryption_configs := {target_bucket |
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.actions[_] != "delete"
    target_bucket := resource.change.after.bucket
}

# Deny if an S3 bucket does not have a server-side encryption configuration resource.
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    resource.change.actions[_] != "delete"

    # Check if a corresponding encryption configuration resource targets this bucket
    not has_encryption_config(resource.address, bucket_encryption_configs)

    msg := sprintf("S3 bucket '%s' must have server-side encryption (SSE) configured.", [resource.address])
}

# Deny if server-side encryption does not use 'aws:kms'.
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.actions[_] != "delete"

    some sse_config in [resource.change.after]
    some rule in sse_config.rule
    some default_encryption in rule.apply_server_side_encryption_by_default

    default_encryption.sse_algorithm != "aws:kms"

    msg := sprintf("S3 bucket encryption configuration '%s' is not using 'aws:kms' for server-side encryption (found '%s').", [resource.address, default_encryption.sse_algorithm])
}

# Deny if the KMS master key ID is missing when using 'aws:kms'.
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.actions[_] != "delete"

    some sse_config in [resource.change.after]
    some rule in sse_config.rule
    some default_encryption in rule.apply_server_side_encryption_by_default

    default_encryption.sse_algorithm == "aws:kms"
    
    # Ensure kms_master_key_id is either missing or empty
    not default_encryption.kms_master_key_id

    msg := sprintf("S3 bucket encryption configuration '%s' must specify a 'kms_master_key_id' when using 'aws:kms'.", [resource.address])
}

# Helper to safely match bucket reference strings
has_encryption_config(bucket_address, configs) if {
    some config_bucket in configs
    contains(config_bucket, split(bucket_address, ".")[1])
}