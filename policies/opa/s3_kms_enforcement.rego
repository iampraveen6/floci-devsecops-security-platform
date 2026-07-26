package terraform.analysis

import rego.v1

# Deny if an S3 bucket does not have server-side encryption configured.
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    resource.change.actions[_] != "delete"

    # Check if server-side encryption configuration is missing or null
    not resource.change.after.server_side_encryption_configuration

    msg := sprintf("S3 bucket '%s' must have server-side encryption (SSE) configured.", [resource.address])
}

# Deny if server-side encryption does not use 'aws:kms'.
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    resource.change.actions[_] != "delete"

    some sse_config in resource.change.after.server_side_encryption_configuration
    some rule in sse_config.rule
    some default_encryption in rule.apply_server_side_encryption_by_default

    default_encryption.sse_algorithm != "aws:kms"

    msg := sprintf("S3 bucket '%s' is not using 'aws:kms' for server-side encryption (found '%s').", [resource.address, default_encryption.sse_algorithm])
}

# Deny if the KMS master key ID is missing when using 'aws:kms'.
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    resource.change.actions[_] != "delete"

    some sse_config in resource.change.after.server_side_encryption_configuration
    some rule in sse_config.rule
    some default_encryption in rule.apply_server_side_encryption_by_default

    default_encryption.sse_algorithm == "aws:kms"
    
    # Ensure kms_master_key_id is either missing or empty
    not default_encryption.kms_master_key_id

    msg := sprintf("S3 bucket '%s' must specify a 'kms_master_key_id' when using 'aws:kms'.", [resource.address])
}