# floci-devsecops-security-platform

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

## Local AWS CLI Security Audit Commands

To run a local security audit against the Floci environment, use the provided script. This script leverages the AWS CLI configured to target the local Floci endpoint.

**Prerequisites**:
- AWS CLI installed and configured.
- Floci container running (`docker run -d -p 4566:4566 floci/floci:latest`).

**Execution**:

```bash
# Make the script executable
chmod +x scripts/floci-security-audit.sh

# Run the audit
./scripts/floci-security-audit.sh
```

This script will:
1. Verify the status of the customer-managed KMS key.
2. Audit S3 buckets for public access blocks.
3. Check IAM permissions for secret retrieval.
4. Output a compliance report to the console.
