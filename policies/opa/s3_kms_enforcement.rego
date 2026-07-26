package terraform.analysis

import rego.v1

# Deny if an S3 bucket does not have a corresponding server-side encryption resource.
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    resource.change.actions[_] != "delete"

    # Check if any sse configuration references this bucket name in its address or dependencies
    bucket_name := split(resource.address, ".")[1]
    not sse_config_exists_for(bucket_name)

    msg := sprintf("S3 bucket '%s' must have server-side encryption (SSE) configured.", [resource.address])
}

sse_config_exists_for(bucket_name) if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.actions[_] != "delete"
    contains(resource.address, bucket_name)
}

# Deny if standard buckets do not use 'aws:kms' (excluding log buckets)
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.actions[_] != "delete"
    
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
    
    # Check if kms_master_key_id is null, missing, or empty
    not default_encryption.kms_master_key_id

    msg := sprintf("S3 bucket encryption configuration '%s' must specify a 'kms_master_key_id'.", [resource.address])
}