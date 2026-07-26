#!/bin/bash

# Floci Local Security Audit Script
# This script verifies the security configuration of the local AWS environment.

# --- Configuration ---
ENDPOINT_URL="http://localhost:4566"
AWS_CMD="aws --endpoint-url=$ENDPOINT_URL --region us-east-1"
BUCKET_NAME="floci-devsecops-audit-logs"
SECRET_NAME="dev/database/credentials"
POLICY_NAME="SecretReaderPolicy"

FAIL_COUNT=0

# --- Colors for Output ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Helper Functions ---
function check_command() {
  if ! command -v $1 &> /dev/null; then
    echo -e "${RED}Error: '$1' command not found. Please install it to run this script.${NC}"
    exit 1
  fi
}

# --- Pre-flight Checks ---
check_command aws
check_command jq

# --- Audit Execution ---
echo "================================================="
echo "   Floci Local Security Compliance Audit Report   "
echo "================================================="
echo

# 1. Verify KMS Key Status
echo -e "${YELLOW}1. Verifying KMS Key Status...${NC}"
# In a local env, we assume the first key created is the one we need.
KEY_ID=$($AWS_CMD kms list-keys --query 'Keys[0].KeyId' --output text)

if [ -z "$KEY_ID" ] || [ "$KEY_ID" == "None" ]; then
  echo -e "   ${RED}[FAIL]${NC} No KMS keys found."
  FAIL_COUNT=$((FAIL_COUNT+1))
else
  KEY_METADATA=$($AWS_CMD kms describe-key --key-id "$KEY_ID")
  KEY_STATE=$(echo "$KEY_METADATA" | jq -r '.KeyMetadata.KeyState')
  ROTATION_STATUS=$($AWS_CMD kms get-key-rotation-status --key-id "$KEY_ID" 2>/dev/null | jq -r '.KeyRotationEnabled // "unknown"')

  if [ "$KEY_STATE" == "Enabled" ]; then
    echo -e "   ${GREEN}[PASS]${NC} KMS Key ($KEY_ID) is enabled."
  else
    echo -e "   ${RED}[FAIL]${NC} KMS Key ($KEY_ID) is not enabled. State: $KEY_STATE."
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi

  if [ "$ROTATION_STATUS" == "true" ]; then
    echo -e "   ${GREEN}[PASS]${NC} KMS Key rotation is enabled."
  elif [ "$ROTATION_STATUS" == "false" ]; then
    echo -e "   ${RED}[FAIL]${NC} KMS Key rotation is not enabled."
  FAIL_COUNT=$((FAIL_COUNT+1))
  else
    echo -e "   ${YELLOW}[INFO]${NC} KMS Key rotation status not reported by local Floci."
  fi
fi
echo

# 2. Audit S3 Bucket Public Access Blocks
echo -e "${YELLOW}2. Auditing S3 Bucket Public Access Blocks...${NC}"
if $AWS_CMD s3api head-bucket --bucket "$BUCKET_NAME" &> /dev/null; then
  PAB_CONFIG=$($AWS_CMD s3api get-public-access-block --bucket "$BUCKET_NAME")
  BLOCK_PUBLIC_ACLS=$(echo "$PAB_CONFIG" | jq -r '.PublicAccessBlockConfiguration.BlockPublicAcls')
  BLOCK_PUBLIC_POLICY=$(echo "$PAB_CONFIG" | jq -r '.PublicAccessBlockConfiguration.BlockPublicPolicy')
  RESTRICT_PUBLIC_BUCKETS=$(echo "$PAB_CONFIG" | jq -r '.PublicAccessBlockConfiguration.RestrictPublicBuckets')

  if [ "$BLOCK_PUBLIC_ACLS" == "true" ] && [ "$BLOCK_PUBLIC_POLICY" == "true" ] && [ "$RESTRICT_PUBLIC_BUCKETS" == "true" ]; then
    echo -e "   ${GREEN}[PASS]${NC} S3 bucket '$BUCKET_NAME' has all public access blocks enabled."
  else
    echo -e "   ${RED}[FAIL]${NC} S3 bucket '$BUCKET_NAME' has insecure public access settings."
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
else
    echo -e "   ${RED}[FAIL]${NC} S3 bucket '$BUCKET_NAME' not found."
    FAIL_COUNT=$((FAIL_COUNT+1))
fi
echo

# 3. Check Secret Retrieval Permissions
echo -e "${YELLOW}3. Checking IAM Policy for Secret Retrieval...${NC}"
POLICY_ARN=$($AWS_CMD iam list-policies --query "Policies[?PolicyName=='$POLICY_NAME'].Arn" --output text)

if [ -z "$POLICY_ARN" ] || [ "$POLICY_ARN" == "None" ]; then
  echo -e "   ${RED}[FAIL]${NC} IAM policy '$POLICY_NAME' not found."
  FAIL_COUNT=$((FAIL_COUNT+1))
else
  POLICY_VERSION=$($AWS_CMD iam get-policy --policy-arn "$POLICY_ARN" --query 'Policy.DefaultVersionId' --output text)
  POLICY_DOC=$($AWS_CMD iam get-policy-version --policy-arn "$POLICY_ARN" --version-id "$POLICY_VERSION" --output json)
  
  SECRET_ARN=$($AWS_CMD secretsmanager describe-secret --secret-id "$SECRET_NAME" --query ARN --output text)

  # Safe jq query: handles both array/string Action and Resource definitions without bash syntax clashing
  MATCHED_RESOURCES=$(echo "$POLICY_DOC" | jq -r '.. | select(type == "object" and .Action != null) | select((.Action | type == "array" and contains(["secretsmanager:GetSecretValue"])) or .Action == "secretsmanager:GetSecretValue") | .Resource | if type == "array" then .[] else . end' 2>/dev/null)

  IS_MATCH=false
  while read -r res; do
    if [ "$res" == "$SECRET_ARN" ] || [ "$res" == "*" ]; then
      IS_MATCH=true
      break
    fi
  done <<< "$MATCHED_RESOURCES"

  if [ "$IS_MATCH" = true ]; then
    echo -e "   ${GREEN}[PASS]${NC} IAM policy '$POLICY_NAME' correctly grants GetSecretValue to the specific secret."
  else
    echo -e "   ${RED}[FAIL]${NC} IAM policy '$POLICY_NAME' does not correctly scope GetSecretValue permissions."
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
fi
echo

# 4. Check AWS GuardDuty Detector Status
echo -e "${YELLOW}4. Checking AWS GuardDuty Detector Status...${NC}"
DETECTORS=$($AWS_CMD guardduty list-detectors --query 'DetectorIds' --output json 2>/dev/null)

if [ -n "$DETECTORS" ] && [ "$DETECTORS" != "[]" ] && [ "$DETECTORS" != "None" ]; then
  echo -e "   ${GREEN}[PASS]${NC} GuardDuty detector(s) found: $DETECTORS."
else
  echo -e "   ${YELLOW}[INFO]${NC} GuardDuty detector not found (service not emulated by local Floci)."
fi
echo

echo "================================================="
echo "               Audit Report Complete             "
echo "================================================="

if [ $FAIL_COUNT -gt 0 ]; then
  echo -e "${RED}Audit completed with $FAIL_COUNT failure(s).${NC}"
  exit 1
fi