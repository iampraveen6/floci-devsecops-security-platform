# floci-devsecops-security-platform

[![DevSecOps Security Gate](https://github.com/iampraveen6/floci-devsecops-security-platform/actions/workflows/devsecops-security-gate.yml/badge.svg)](https://github.com/iampraveen6/floci-devsecops-security-platform/actions/workflows/devsecops-security-gate.yml)

A production-ready GitHub repository for DevSecOps, Application Security, Supply Chain Security, and Policy-as-Code, using the Floci AWS Local Skill baseline.

## DevSecOps Architecture Overview

This repository provides a comprehensive, automated security platform for local development and testing against an AWS-compatible environment simulated by Floci. The architecture is designed to shift security left, integrating security controls directly into the development lifecycle.

Key capabilities include:
- **Pre-Commit/PR Security Gates**: Automated secret scanning (Gitleaks) and static analysis (Trivy) to catch vulnerabilities before they enter the codebase.
- **Infrastructure as Code (IaC) Security**: Policy-as-Code (PaC) enforcement using Checkov and Open Policy Agent (OPA) to validate Terraform configurations against security best practices.
- **Supply Chain Security**: Container image scanning (Trivy), Software Bill of Materials (SBOM) generation (Syft), and container signing concepts to secure the software supply chain.
- **Local SecOps & Auditing**: Automated scripts to audit the local Floci environment for compliance with security policies, including KMS key status, S3 bucket policies, and IAM permissions.

## Threat Model Summary

A detailed STRIDE threat model analysis is available in `docs/DEVSECOPS_THREAT_MODEL_AND_POLICIES.md`. The model focuses on threats relevant to a local development environment that mimics cloud services, including:

- **Spoofing**: Unauthorized access to local AWS services.
- **Tampering**: Unauthorized modification of IaC files, container images, or application code.
- **Repudiation**: Lack of audit trails for security-related events.
- **Information Disclosure**: Exposure of secrets, sensitive data, or infrastructure misconfigurations.
- **Denial of Service**: Disruption of local services through misconfiguration or resource exhaustion.
- **Elevation of Privilege**: Gaining unauthorized permissions within the local AWS environment.

## Pipeline Security Gates Diagram

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

## Local Development & Audit

This section provides a complete guide to setting up your local environment to run the security audit against a local Floci instance. These steps replicate the environment used in the GitHub Actions CI pipeline.

### Prerequisites

Ensure the following tools are installed on your system (WSL is recommended on Windows):

1.  **Docker**: To run the Floci container.
2.  **AWS CLI v2**: For interacting with the local AWS environment.
3.  **jq**: A command-line JSON processor used by the audit script.
4.  **Terraform**: To deploy the IaC resources to the local Floci environment.

### Step-by-Step Guide

1.  **Start the Floci Container**:

    Open a terminal and run the following command to start the Floci container in the background. This simulates the AWS environment locally.

    ```bash
    docker run --rm -d -v /var/run/docker.sock:/var/run/docker.sock -p 4566:4566 -p 4510-4559:4510-4559 --name floci floci/floci:latest
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

### Run the container

Start the application in the background and map port `5000`:

```bash
docker run -d -p 5000:5000 --name sample-app sample-app:latest
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

## One-Command Local Setup

A `Makefile` is included to simplify the local Floci workflow:

- `make start-floci` — start the Floci container
- `make deploy` — start Floci and run Terraform apply
- `make audit` — run the security audit script
- `make stop-floci` — stop and remove the container
- `make all` — start, deploy, and audit in one command

Example:

```bash
make all
```

## Slack Failure Notifications

The pipeline includes a `notify-on-failure` job that sends a Slack message when any job fails. To enable it, add a repository secret named `SLACK_WEBHOOK_URL` under **Settings > Secrets and variables > Actions**.
