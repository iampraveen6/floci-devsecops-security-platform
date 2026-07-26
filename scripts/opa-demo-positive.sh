#!/usr/bin/env bash
set -e

echo "=== OPA Positive Case ==="
echo "S3 bucket with a matching aws:kms server-side encryption configuration."
docker run --rm \
  -v "$(pwd)/policies/opa:/policies" \
  openpolicyagent/opa:latest test -r test_positive -v /policies

echo "Positive case passed: the compliant plan is allowed."
