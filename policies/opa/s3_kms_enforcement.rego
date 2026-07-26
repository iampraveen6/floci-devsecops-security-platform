package terraform.analysis

import rego.v1

# Deny if an S3 bucket does not have a server-side encryption resource configuration.
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    resource.change.actions[_] != "delete"

    # Check if a corresponding encryption configuration resource exists for this bucket
    bucket_name := split(resource.address, ".")[1]
    not encryption_config_exists(bucket_name)

    msg := sprintf("S3 bucket '%s' must have server-side encryption (SSE) configured.", [resource.address])
}

encryption_config_exists(bucket_name) if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.actions[_] != "delete"
    contains(resource.change.after.bucket, bucket_name)
}

# Deny if standard buckets do not use 'aws:kms' (excluding log buckets which use AES256 intentionally)
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.actions[_] != "delete"
    
    # Skip log bucket from requiring aws:kms since it uses AES256 intentionally
    not contains(resource.address, "log_bucket")

    some sse_config in [resource.change.after]
    some rule in sse_config.rule
    some default_encryption in rule.apply_server_side_encryption_by_default

    default_encryption.sse_algorithm != "aws:kms"

    msg := sprintf("S3 bucket encryption configuration '%s' must use 'aws:kms'.", [resource.address])
}

# Deny if kms_master_key_id is missing when using 'aws:kms'
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.actions[_] != "delete"

    some sse_config in [resource.change.after]
    some rule in sse_config.rule
    some default_encryption in rule.apply_server_side_encryption_by_default

    default_encryption.sse_algorithm == "aws:kms"
    not default_encryption.kms_master_key_id

    msg := sprintf("S3 bucket encryption configuration '%s' must specify a 'kms_master_key_id'.", [resource.address])
}