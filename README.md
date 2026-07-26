# floci-devsecops-security-platform

[![DevSecOps Security Gate](https://github.com/iampraveen6/floci-devsecops-security-platform/actions/workflows/devsecops-security-gate.yml/badge.svg)](https://github.com/iampraveen6/floci-devsecops-security-platform/actions/workflows/devsecops-security-gate.yml)

A production-ready GitHub repository for DevSecOps, Application Security, Supply Chain Security, and Policy-as-Code, using the Floci AWS Local Skill baseline.

## Table of Contents

- [Quick Start](#quick-start)
- [What is this?](#what-is-this)
- [Architecture Overview](#architecture-overview)
- [Project Structure](#project-structure)
- [Technology Stack & Versions](#technology-stack--versions)
- [CI/CD Pipeline](#cicd-pipeline)
- [Security Threat Model](#security-threat-model)
- [What Terraform Deploys](#what-terraform-deploys)
- [OPA / Rego Policy](#opa--rego-policy)
- [Local Setup](#local-setup)
- [Security Audit](#security-audit)
- [Sample Application](#sample-application)
- [Floci Web UI](#floci-web-ui)
- [Manual Rollback Workflow](#manual-rollback-workflow)
- [Environment Variables](#environment-variables)
- [Troubleshooting](#troubleshooting)
- [Interview / Demo Talking Points](#interview--demo-talking-points)
- [Notifications](#notifications)

## Quick Start

One command starts Floci, builds and runs the sample app, deploys the Terraform resources, and runs the security audit:

```bash
make all
```

Common `Makefile` helpers:

```bash
make start-floci      # clean up and start the Floci container
make deploy           # start Floci and deploy Terraform
make audit            # run the security audit script
make build-sample-app # build the sample Flask Docker image
make run-sample-app   # build and run the sample Flask container
make all              # start Floci, build/run sample app, deploy, and audit
make stop-floci       # stop and remove the Floci container
make clean            # alias for stop-floci
```


## What is this?

This repository provides a comprehensive, automated security platform for local development and testing against an AWS-compatible environment simulated by Floci. The architecture is designed to shift security left, integrating security controls directly into the development lifecycle.

Key capabilities include:
- **Pre-Commit/PR Security Gates**: Automated secret scanning (Gitleaks) and static analysis (Trivy) to catch vulnerabilities before they enter the codebase.
- **Infrastructure as Code (IaC) Security**: Policy-as-Code (PaC) enforcement using Checkov and Open Policy Agent (OPA) to validate Terraform configurations against security best practices.
- **Supply Chain Security**: Container image scanning (Trivy), Software Bill of Materials (SBOM) generation (Syft), and container signing concepts to secure the software supply chain.
- **Local SecOps & Auditing**: Automated scripts to audit the local Floci environment for compliance with security policies, including KMS key status, S3 bucket policies, and IAM permissions.


## Architecture Overview

The following diagram illustrates the security gates integrated into the CI/CD pipeline:

```ascii
+-----------------+      +----------------------+      +-------------------------+
|  Developer Push |----->|  GitHub Actions PR   |----->|  Automated Security     |
| (Pre-commit Hooks)|      |  Workflow Triggered  |      |  Gates                  |
+-----------------+      +----------------------+      +-------------------------+
                                                              |
                                                              V
+---------------------------------------------------------------------------------------+
|                                 SECURITY GATES                                        |
|---------------------------------------------------------------------------------------|
| 1. Gitleaks Secret Detection: Scans code for hardcoded secrets.                       |
| 2. Trivy SAST Scan: Analyzes code and dependencies for vulnerabilities.               |
| 3. Checkov IaC Scan: Validates Terraform against 100s of built-in policies.           |
| 4. OPA/Rego IaC Policy: Enforces custom policies (e.g., S3 KMS encryption).           |
| 5. Trivy Container Scan: Scans Docker images for OS and library vulnerabilities.      |
| 6. Syft SBOM Generation: Creates a Software Bill of Materials for dependencies.       |
+---------------------------------------------------------------------------------------+
                                                              |
                                                              V
+-----------------+      +----------------------+      +-------------------------+
|  Merge to Main  |<-----|   All Gates Pass     |<-----|   Local Deployment      |
| (Production-like)|      | (PR Approved)        |      |   (Terraform Apply)     |
+-----------------+      +----------------------+      +-------------------------+
```


## Project Structure

```text
floci-devsecops-security-platform/
├── .github/workflows/
│   ├── devsecops-security-gate.yml   # Main CI/CD security gate
│   └── manual-rollback.yml           # Manual Terraform destroy / rollback
├── app/
│   ├── Dockerfile                    # Hardened container image for sample Flask app
│   ├── main.py                       # Flask /health endpoint
│   └── requirements.txt              # Python dependencies
├── docs/
│   └── DEVSECOPS_THREAT_MODEL_AND_POLICIES.md  # STRIDE threat model + SLAs
├── policies/opa/
│   └── s3_kms_enforcement.rego       # Custom Rego policy for S3 KMS encryption
├── scripts/
│   └── floci-security-audit.sh       # Local AWS compliance audit script
├── terraform/
│   ├── main.tf                       # AWS resources: KMS, S3, Secrets, IAM
│   └── providers.tf                  # Local Floci provider configuration
├── Makefile                          # One-command local workflow helpers
└── README.md                         # This document
```


## Technology Stack & Versions

| Component        | Purpose                                           | Version / Source Used in CI                |
| ---------------- | ------------------------------------------------- | ------------------------------------------ |
| **Docker**       | Run Floci (LocalStack-based AWS mock) locally     | Latest available on host                   |
| **Terraform**    | Infrastructure as Code (IaC) deployment           | `1.15.8`                                   |
| **AWS Provider** | Terraform provider for AWS resources              | `~> 5.0`                                   |
| **Trivy**        | IaC and container vulnerability scanning          | `0.72.0`                                   |
| **Checkov**      | Terraform policy / compliance scanning            | Latest PyPI release                        |
| **OPA**          | Open Policy Agent for custom Rego policies        | `1.8.0`                                    |
| **Gitleaks**     | Secret detection in source code and history       | `gitleaks/gitleaks-action@v2`              |
| **Syft**         | SBOM generation (container supply-chain)          | Via Trivy / workflow                       |
| **Python**       | Sample Flask application runtime                  | `3.13`                                     |
| **Flask**        | Sample web framework                              | `>= 3.0.0`                                 |
| **Gunicorn**     | WSGI server for the sample app                    | `>= 22.0.0`                                |
| **jq**           | JSON parsing in audit and OPA result handling     | Installed on runner / WSL                  |


## CI/CD Pipeline

The `DevSecOps Security Gate` workflow (`.github/workflows/devsecops-security-gate.yml`) runs on every pull request and push to `main`, and can also be triggered manually (`workflow_dispatch`).

### Job 1: Security Scans

Every code change is scanned before it is allowed to deploy.

1. **Checkout** — Full git history is fetched so Gitleaks can scan the entire commit graph.
2. **Environment validation** — Prints runner, Git, Docker, and Terraform versions for reproducibility.
3. **Gitleaks secret detection** — Scans the repository for hardcoded secrets, API keys, and tokens.
4. **Trivy Terraform IaC scan** — Scans `./terraform` for HIGH and CRITICAL misconfigurations.
5. **Checkov Terraform scan** — Runs hundreds of built-in compliance policies against the Terraform code.
6. **Terraform format check** — Runs `terraform fmt -recursive` to enforce consistent formatting.
7. **Terraform init** — Downloads providers with `-backend=false` for local state.
8. **Terraform validate** — Validates configuration syntax and provider requirements.
9. **Terraform plan** — Generates `tfplan.binary` and converts it to `terraform/tfplan.json`.
10. **OPA/Rego policy validation** — `opa check` validates the Rego syntax; `opa eval` evaluates the plan against `s3_kms_enforcement.rego`.
11. **Artifact upload** — The Terraform plan artifacts are uploaded for audit/debug regardless of pass/fail.

### Job 2: Local Floci Deployment

Runs only after `security-scans` succeeds.

1. **Start Floci service container** on `localhost:4566`.
2. **Wait for health endpoint** (`/_localstack/health`) with a 30-attempt retry loop.
3. **Terraform init & apply** against the local Floci endpoints.
4. **Deployment verification** — Runs `terraform output` and confirms resources exist.
5. **Automatic rollback** — If `terraform apply` fails, `terraform destroy` is executed immediately.

### Pipeline Security Principle

**Security failures block deployment.** Any failing gate stops the workflow before infrastructure is deployed.


## Security Threat Model

A detailed STRIDE threat model analysis is available in `docs/DEVSECOPS_THREAT_MODEL_AND_POLICIES.md`. The model focuses on threats relevant to a local development environment that mimics cloud services, including:

- **Spoofing**: Unauthorized access to local AWS services.
- **Tampering**: Unauthorized modification of IaC files, container images, or application code.
- **Repudiation**: Lack of audit trails for security-related events.
- **Information Disclosure**: Exposure of secrets, sensitive data, or infrastructure misconfigurations.
- **Denial of Service**: Disruption of local services through misconfiguration or resource exhaustion.
- **Elevation of Privilege**: Gaining unauthorized permissions within the local AWS environment.


## What Terraform Deploys

`terraform/main.tf` provisions the following resources against the local Floci endpoints:

- **`aws_kms_key.devsecops_key`** — Customer-managed KMS key with `enable_key_rotation = true`.
- **`aws_s3_bucket.audit_bucket`** — `floci-devsecops-audit-logs` with:
  - Object Lock in COMPLIANCE mode (1-year retention)
  - Versioning
  - Public access blocks
  - KMS server-side encryption
  - Bucket policy denying unencrypted or incorrectly encrypted uploads
  - Access logging to `floci-devsecops-access-logs`
- **`aws_s3_bucket.log_bucket`** — `floci-devsecops-access-logs` with:
  - Versioning
  - Public access blocks
  - SSE-S3 (AES256) encryption — required for S3 logging destinations
- **`aws_secretsmanager_secret.database_credentials`** — Secret encrypted with the KMS key.
- **`aws_iam_policy.secret_reader_policy`** — Least-privilege IAM policy allowing `GetSecretValue` and `DescribeSecret` only on the specific secret, plus scoped `kms:Decrypt` via `kms:ViaService`.

### Local Endpoint Configuration

`terraform/providers.tf` points all AWS services to `http://localhost:4566`:

```hcl
endpoints {
  s3             = "http://localhost:4566"
  kms            = "http://localhost:4566"
  secretsmanager = "http://localhost:4566"
  iam            = "http://localhost:4566"
  sts            = "http://localhost:4566"
}
```


## OPA / Rego Policy

`policies/opa/s3_kms_enforcement.rego` enforces three custom controls on the Terraform plan JSON:

1. **Mandatory SSE** — Every `aws_s3_bucket` must have a corresponding `aws_s3_bucket_server_side_encryption_configuration` resource.
2. **KMS Algorithm** — Non-log buckets must use `aws:kms` as the SSE algorithm.
3. **KMS Key Reference** — When `aws:kms` is selected, `kms_master_key_id` must be present (unless it is computed/unknown during plan).

The workflow evaluates the policy with:

```bash
opa eval \
  --input ./terraform/tfplan.json \
  --data ./policies/opa/s3_kms_enforcement.rego \
  'data.terraform.analysis.deny'
```

If the `deny` set is non-empty, the pipeline fails.


## Local Setup

This section provides a complete guide to setting up your local environment to run the security audit against a local Floci instance. These steps replicate the environment used in the GitHub Actions CI pipeline.

### Prerequisites

Ensure the following tools are installed on your system (WSL is recommended on Windows):

1.  **Docker**: To run the Floci container.
2.  **AWS CLI v2**: For interacting with the local AWS environment.
3.  **jq**: A command-line JSON processor used by the audit script.
4.  **Terraform**: To deploy the IaC resources to the local Floci environment.

### Step-by-Step Guide

1.  **Start the Floci Container**:

    Open a terminal and clean up any old Floci container, then start a new one in the background. This simulates the AWS environment locally.

    ```bash
    docker kill floci 2>/dev/null || true
    docker rm floci 2>/dev/null || true
    docker run --rm -d -v /var/run/docker.sock:/var/run/docker.sock -p 4566:4566 --name floci floci/floci:latest
    ```

2.  **Deploy Terraform Resources**:

    Navigate to the `terraform` directory and deploy the AWS resources to the running Floci container.

    ```bash
    cd terraform
    terraform init
    terraform apply -auto-approve
    cd ..
    ```

3.  **Run the Security Audit Script**:

    Execute the audit script from the root of the repository. This script checks if the deployed resources comply with the defined security policies.

    ```bash
    # Make the script executable (if you haven't already)
    chmod +x scripts/floci-security-audit.sh

    # Run the audit
    ./scripts/floci-security-audit.sh
    ```

4.  **Review the Output**:

    The script will output a compliance report to the console. A successful audit will show `[PASS]` for all checks:

    ```text
    =================================================
       Floci Local Security Compliance Audit Report
    =================================================

    1. Verifying KMS Key Status...
       [PASS] KMS Key (...) is enabled.
       [PASS] KMS Key rotation is enabled.

    2. Auditing S3 Bucket Public Access Blocks...
       [PASS] S3 bucket 'floci-devsecops-audit-logs' has all public access blocks enabled.

    3. Checking IAM Policy for Secret Retrieval...
       [PASS] IAM policy 'SecretReaderPolicy' correctly grants GetSecretValue to the specific secret.

    =================================================
                   Audit Report Complete
    =================================================
    ```


## Security Audit

`scripts/floci-security-audit.sh` is the post-deploy compliance check. It performs three checks against `http://localhost:4566`:

1. **KMS Key Status** — Verifies the first KMS key is `Enabled` and that key rotation is enabled.
2. **S3 Public Access Block** — Confirms `floci-devsecops-audit-logs` has `BlockPublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets` set to `true`.
3. **IAM Secret Retrieval** — Validates `SecretReaderPolicy` grants `secretsmanager:GetSecretValue` scoped to the exact secret ARN (`dev/database/credentials`).

The script exits with `0` regardless of individual findings (it reports `PASS`/`FAIL` to the console) so it can be used for demonstration and reporting.


## Sample Application

A minimal containerized Flask application is provided in `app/`. It exposes a `/health` endpoint and is built and scanned by the Trivy container vulnerability scan in the CI pipeline.

### Application Details

- **Language/Framework**: Python 3 with Flask.
- **Endpoint**: `GET /health` returns a JSON health-check response.
- **Files**:
  - `app/main.py` — Flask application entry point.
  - `app/requirements.txt` — Python dependencies (Flask, Gunicorn).
  - `app/Dockerfile` — container build based on `python:3.13-slim` and runs as a non-root user.
- **CI integration**: The `DevSecOps Security Gate` workflow builds the Docker image and runs a Trivy container vulnerability scan to demonstrate supply-chain security.

### Prerequisites

- Docker installed and running.

### Build the Docker image

From the repository root, run:

```bash
docker build -t sample-app:latest ./app
```

Or use the Makefile helper:

```bash
make build-sample-app
```

### Run the container

Start the application in the background and map port `5000`:

```bash
docker run -d -p 5000:5000 --name sample-app sample-app:latest
```

Or use the Makefile helper, which rebuilds the image first and replaces any existing container:

```bash
make run-sample-app
```

### Test the endpoint

Once the container is running, verify it with `curl`:

```bash
curl http://localhost:5000/health
```

Expected response:

```json
{"status":"ok"}
```

You can also open `http://localhost:5000/health` in your browser.

### View logs

```bash
docker logs -f sample-app
```

### Stop and remove the container

```bash
docker stop sample-app
docker rm sample-app
```


## Floci Web UI

When you start Floci with the Docker socket mounted, it exposes a local web dashboard at:

```text
http://localhost:4566/
```

The dashboard lets you browse the locally emulated AWS services (S3, KMS, IAM, Secrets Manager, and more) and inspect the resources deployed by Terraform. It is a convenient way to visually verify the local infrastructure before or after running the audit script.

To access it:

1. Start the Floci container using the command from the [Local Development & Audit](#local-development--audit) section (which already mounts `/var/run/docker.sock`).
2. Open `http://localhost:4566/` in your browser.
3. Navigate through the service list to view buckets, KMS keys, IAM policies, and secrets.


## Manual Rollback Workflow

`.github/workflows/manual-rollback.yml` allows operators to tear down infrastructure safely.

- **Trigger**: `workflow_dispatch` with two inputs:
  - `target_environment`: `local-floci`, `staging`, or `production`
  - `confirm_rollback`: must be the exact string `ROLLBACK`
- **Safety guard**: The workflow aborts if the confirmation string does not match.
- **For `local-floci`**: It starts a fresh Floci container, runs `terraform init -backend=false`, then `terraform destroy -auto-approve`.
- **Audit log**: Writes rollback metadata (`Triggered By`, `Target Environment`, `Status`) to `$GITHUB_STEP_SUMMARY`.

To run it, go to **Actions > Manual Infrastructure Rollback > Run workflow** in the GitHub UI.


## Environment Variables

### CI/CD Variables (GitHub Actions)

These are set automatically in the workflow; you do not need to set them locally for CI:

| Variable                    | Value                 | Purpose                                  |
| --------------------------- | --------------------- | ---------------------------------------- |
| `AWS_ACCESS_KEY_ID`         | `test`                | Dummy access key for Floci               |
| `AWS_SECRET_ACCESS_KEY`     | `test`                | Dummy secret key for Floci               |
| `AWS_DEFAULT_REGION`        | `us-east-1`           | Region used by Terraform and AWS CLI     |
| `AWS_ENDPOINT_URL_S3`       | `http://localhost:4566` | S3 endpoint override                    |
| `AWS_ENDPOINT_URL_KMS`      | `http://localhost:4566` | KMS endpoint override                   |
| `AWS_ENDPOINT_URL_SECRETSMANAGER` | `http://localhost:4566` | Secrets Manager endpoint override       |
| `AWS_ENDPOINT_URL_IAM`      | `http://localhost:4566` | IAM endpoint override                   |
| `AWS_ENDPOINT_URL_STS`      | `http://localhost:4566` | STS endpoint override                   |

### Local AWS CLI Overrides

When running `aws` CLI commands against Floci manually, use `--endpoint-url`:

```bash
aws --endpoint-url=http://localhost:4566 --region us-east-1 s3api list-buckets
```


## Troubleshooting

### `Conflict. The container name "/floci" is already in use`

The `Makefile` now kills and removes any existing `floci` container before starting. If you still see this error, run manually:

```bash
docker kill floci 2>/dev/null || true
docker rm floci 2>/dev/null || true
```

### `make` fails with `terraform` not found

Install Terraform `1.15.8` or later and ensure it is on your `PATH`:

```bash
terraform version
```

### AWS CLI returns `Unable to locate credentials`

For local Floci, export dummy credentials:

```bash
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
```

### Audit script reports `[FAIL] S3 bucket not found`

Run `make deploy` or `terraform apply` first. The audit script only verifies resources that have already been provisioned.

### Floci dashboard is unreachable

Wait 5–10 seconds after `make start-floci`, then open `http://localhost:4566/`. If it still fails, check the container logs:

```bash
docker logs floci
```

### Policy-as-Code failures locally

Ensure OPA is installed and the Rego policy is syntactically valid:

```bash
opa check ./policies/opa
```


## Interview / Demo Talking Points

Use these points when presenting the repository:

- **Shift-Left Security**: Security gates run before any infrastructure is deployed, not after.
- **Defense in Depth**: Multiple scanners (Gitleaks, Trivy, Checkov, OPA) cover secrets, vulnerabilities, IaC misconfigurations, and custom policies.
- **Policy-as-Code**: OPA/Rego codifies the requirement that every S3 bucket must be encrypted with a customer-managed KMS key.
- **Least Privilege**: The IAM policy grants access to exactly one secret and uses `kms:ViaService` to scope KMS decrypt permissions.
- **Immutable Audit Logs**: S3 Object Lock in COMPLIANCE mode protects audit logs from deletion or modification.
- **Supply Chain Security**: Container image scanning with Trivy and SBOM generation (Syft) protect the build pipeline.
- **Automated Rollback**: CI automatically destroys resources if `terraform apply` fails, preventing partial/unsafe states.
- **Local-First, Production-Ready Concepts**: Floci simulates AWS locally, but the same controls (KMS, IAM least privilege, encryption, logging) map directly to real AWS deployments.


## Notifications

The pipeline includes a `notify-on-failure` job that sends a Slack message when any job fails. To enable it, add a repository secret named `SLACK_WEBHOOK_URL` under **Settings > Secrets and variables > Actions**.
