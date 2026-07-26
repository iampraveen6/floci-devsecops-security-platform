#!/usr/bin/env bash
set -e

echo "=== OPA Negative Case ==="
echo "S3 bucket without a server-side encryption configuration."
docker run --rm \
  -v "$(pwd)/policies/opa:/policies" \
  openpolicyagent/opa:latest test -r test_negative -v /policies

echo "Negative case passed: the non-compliant plan is denied."
