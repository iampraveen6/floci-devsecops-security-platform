package terraform.analysis

import rego.v1

# Deny if an S3 bucket does not have a corresponding server-side encryption resource.
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    resource.change.actions[_] != "delete"

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

# Deny if kms_master_key_id is missing and is NOT a computed value during plan
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.actions[_] != "delete"

    some sse_config in [resource.change.after]
    some rule in sse_config.rule
    some default_encryption in rule.apply_server_side_encryption_by_default

    default_encryption.sse_algorithm == "aws:kms"
    
    # Pass resource to evaluate both 'after' and 'after_unknown'
    missing_key_id(resource)

    msg := sprintf("S3 bucket encryption configuration '%s' must specify a 'kms_master_key_id'.", [resource.address])
}

# Helper: Key is missing if absent/empty in 'after' AND not being dynamically created in 'after_unknown'
missing_key_id(resource) if {
    some sse_config in [resource.change.after]
    some rule in sse_config.rule
    some default_encryption in rule.apply_server_side_encryption_by_default

    # 1. Not defined or empty in 'after'
    is_empty_or_null(default_encryption)

    # 2. Not marked as a known-after-apply/computed value in 'after_unknown'
    not is_computed_in_after_unknown(resource)
}

is_empty_or_null(encryption_obj) if {
    not encryption_obj.kms_master_key_id
}

is_empty_or_null(encryption_obj) if {
    encryption_obj.kms_master_key_id == ""
}

is_computed_in_after_unknown(resource) if {
    some rule in resource.change.after_unknown.rule
    some default_enc in rule.apply_server_side_encryption_by_default
    default_enc.kms_master_key_id == true
}