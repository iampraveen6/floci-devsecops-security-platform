package terraform.analysis

import rego.v1

# 1. Deny if an S3 bucket does not have a corresponding server-side encryption resource.
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

# 2. Deny if standard buckets do not use 'aws:kms' (excluding log buckets)
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

# 3. Deny if kms_master_key_id is missing and is NOT a computed value during plan
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.actions[_] != "delete"

    # Ensure this bucket is configured for KMS
    some rule in resource.change.after.rule
    some default_encryption in rule.apply_server_side_encryption_by_default
    default_encryption.sse_algorithm == "aws:kms"

    # Fail if key ID is missing in static configuration AND not computed in plan
    key_is_missing(default_encryption)
    not key_is_computed(resource)

    msg := sprintf("S3 bucket encryption configuration '%s' must specify a 'kms_master_key_id'.", [resource.address])
}

# Helper: Checks if kms_master_key_id is absent, null, or empty string in 'change.after'
key_is_missing(encryption_obj) if {
    not encryption_obj.kms_master_key_id
}

key_is_missing(encryption_obj) if {
    encryption_obj.kms_master_key_id == ""
}

# Helper: Checks safely if kms_master_key_id is marked as computed/unknown in 'change.after_unknown'
key_is_computed(resource) if {
    after_unknown := object.get(resource.change, "after_unknown", {})
    rules := object.get(after_unknown, "rule", [])
    some rule in rules
    defaults := object.get(rule, "apply_server_side_encryption_by_default", [])
    some enc in defaults
    enc.kms_master_key_id == true
}

# Standard boolean rule to determine overall evaluation success
default allow = false

allow if {
    count(deny) == 0
}