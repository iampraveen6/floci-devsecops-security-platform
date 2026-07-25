# OPA/Rego Policy: Enforce KMS Encryption on S3 Buckets

package terraform.analysis

# Deny if an S3 bucket does not have server-side encryption configured with KMS.
deny[msg] {
    # Find all S3 bucket resources
    resource := input.resource.aws_s3_bucket[_]

    # Check if a server-side encryption configuration is missing
    not resource.server_side_encryption_configuration

    # Format the denial message
    msg := sprintf("S3 bucket '%s' must have server-side encryption (SSE) with KMS enabled.", [resource.name])
}

# Deny if the server-side encryption configuration does not use 'aws:kms'.
deny[msg] {
    # Find all S3 bucket resources with SSE configuration
    resource := input.resource.aws_s3_bucket[_]
    sse_config := resource.server_side_encryption_configuration[_]

    # Check if the algorithm is not 'aws:kms'
    sse_config.rule[_].apply_server_side_encryption_by_default[_].sse_algorithm != "aws:kms"

    # Format the denial message
    msg := sprintf("S3 bucket '%s' is not using 'aws:kms' for server-side encryption.", [resource.name])
}

# Deny if the KMS key ID is missing from the encryption configuration.
deny[msg] {
    # Find all S3 bucket resources with SSE configuration
    resource := input.resource.aws_s3_bucket[_]
    sse_config := resource.server_side_encryption_configuration[_]

    # Ensure the algorithm is 'aws:kms' before checking for the key
    rule := sse_config.rule[_]
    rule.apply_server_side_encryption_by_default[_].sse_algorithm == "aws:kms"

    # Check if the kms_master_key_id is missing or empty
    not rule.apply_server_side_encryption_by_default[_].kms_master_key_id

    # Format the denial message
    msg := sprintf("S3 bucket '%s' must specify a 'kms_master_key_id' for SSE.", [resource.name])
}
