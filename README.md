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

## Sample Application

A minimal containerized Flask application is provided in `app/`. The CI pipeline builds the image and runs a Trivy container vulnerability scan.

To build and test it locally:

```bash
docker build -t sample-app ./app
docker run -p 5000:5000 sample-app
```

Then open `http://localhost:5000/health`.

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
