# DevSecOps Threat Model and Policies

This document outlines the threat model, vulnerability management policies, and secrets governance for the Floci DevSecOps Security Platform.

## 1. STRIDE Threat Model Analysis

The STRIDE model is used to identify and categorize potential threats to the system. The analysis below is tailored to the context of a local development environment using Floci to simulate AWS services.

| STRIDE Category         | Threat Description                                                                                             | Mitigation Strategy                                                                                                                                                                                                                                                                                                                                                                                       |
| ----------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Spoofing**            | An attacker impersonates a legitimate user or service to gain unauthorized access to the local Floci environment.    | - **IAM Least Privilege**: Enforce strict IAM policies with condition keys to limit resource access.<br>- **Pre-commit Hooks**: Use Gitleaks to prevent AWS credentials from being committed.<br>- **MFA (Conceptual)**: While not implemented locally, production environments should enforce Multi-Factor Authentication.                                                                                             |
| **Tampering**           | An attacker modifies IaC files, application code, or container images to inject malicious code or misconfigurations. | - **Version Control**: Use signed commits to ensure code integrity.<br>- **CI/CD Security Gates**: Run Checkov and OPA to detect unauthorized or insecure changes to Terraform code.<br>- **Container Image Signing**: Implement Cosign/Notary to sign and verify container images before deployment.<br>- **S3 Object Lock**: Enable Compliance mode on the audit S3 bucket to prevent log tampering.                 |
| **Repudiation**         | An actor (malicious or accidental) performs an action without a sufficient audit trail, making it impossible to trace. | - **Centralized Logging**: Configure all services to send logs to a central S3 bucket.<br>- **CloudTrail (Conceptual)**: In a real AWS environment, enable CloudTrail for all API actions.<br>- **Immutable Audit Logs**: Use S3 Object Lock to ensure audit logs cannot be deleted or modified.                                                                                                                            |
| **Information Disclosure** | Sensitive information, such as secrets, PII, or infrastructure details, is exposed to unauthorized parties.      | - **Secret Scanning**: Integrate Gitleaks into the pre-commit and CI pipeline to detect hardcoded secrets.<br>- **Secrets Management**: Use AWS Secrets Manager with KMS encryption for all secrets.<br>- **Data Encryption**: Enforce KMS encryption for all S3 buckets and other data stores.<br>- **IaC Scanning**: Use Checkov to identify misconfigurations like public S3 buckets or unencrypted resources. |
| **Denial of Service**   | An attacker disrupts the availability of local services through misconfiguration or resource exhaustion.             | - **Resource Validation**: Use Terraform `validate` and Checkov to catch syntax errors and misconfigurations.<br>- **Rate Limiting (Conceptual)**: In production, configure rate limiting on public-facing endpoints (e.g., API Gateway).<br>- **Scalability**: Design infrastructure to be scalable and resilient (e.g., Auto Scaling Groups).                                                                                             |
| **Elevation of Privilege** | An attacker gains a higher level of permissions than they are authorized for.                                    | - **IAM Least Privilege**: Adhere strictly to the principle of least privilege. Avoid wildcard permissions.<br>- **Regular Audits**: Use the `floci-security-audit.sh` script to regularly review permissions and configurations.<br>- **Separation of Duties**: Define distinct IAM roles for different functions (e.g., CI/CD, developers, auditors).                                                                              |

## 2. Vulnerability Severity SLA Matrix

This matrix defines the Service Level Agreements (SLAs) for remediating vulnerabilities based on their severity. The clock starts when a vulnerability is identified by a security tool (e.g., Trivy, Checkov).

| Severity   | CVSS Score | Remediation SLA (Business Days) | Description                                                                                                                                    |
| ---------- | ---------- | ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| **Critical** | 9.0 - 10.0 | 1 Day                           | Vulnerabilities that can be easily exploited by an unauthenticated attacker, leading to a full system compromise, data exfiltration, or DoS.      |
| **High**     | 7.0 - 8.9  | 7 Days                          | Vulnerabilities that are difficult to exploit but could result in significant impact, or are easy to exploit with limited impact.                |
| **Medium**   | 4.0 - 6.9  | 30 Days                         | Vulnerabilities that require local or privileged access to exploit, or have limited impact on the system's confidentiality, integrity, or availability. |
| **Low**      | 0.1 - 3.9  | 90 Days                         | Vulnerabilities with minimal impact, such as informational findings or security best practice recommendations.                               |
| **None**     | 0.0        | N/A                             | Informational findings that do not pose a security risk.                                                                                       |

**Policy**: Any `Critical` or `High` vulnerability identified in the CI/CD pipeline **must** block the build. Pull requests with unaddressed Critical/High findings will not be approved for merge.

## 3. Secrets Management Governance

This section outlines the policies for managing secrets within the Floci DevSecOps Security Platform.

1.  **Zero Hardcoded Secrets**: Under no circumstances should secrets (API keys, passwords, credentials) be hardcoded in source code, configuration files, or environment variables. All secrets must be stored in AWS Secrets Manager.

2.  **Detection**: The `Gitleaks` scanner is integrated into the pre-commit hooks and the CI/CD pipeline to automatically detect and block commits containing hardcoded secrets.

3.  **Storage and Encryption**:
    - All secrets must be stored in AWS Secrets Manager.
    - All secrets must be encrypted at rest using a customer-managed KMS key.
    - The KMS key must have key rotation enabled.

4.  **Access Control**:
    - Access to secrets must be granted based on the principle of least privilege.
    - IAM policies must be used to control which users, roles, and services can retrieve specific secrets.
    - IAM policies should be as specific as possible, granting access only to the required secrets (e.g., `arn:aws:secretsmanager:us-east-1:000000000000:secret:my-app/prod/api-key-??????`).

5.  **Rotation**:
    - Where possible, automated secret rotation should be enabled for secrets stored in Secrets Manager.
    - For secrets that cannot be rotated automatically, a manual rotation schedule must be established based on the sensitivity of the secret (e.g., every 90 days).

6.  **Auditing**:
    - All access to secrets must be logged and monitored.
    - Regular audits should be performed to review who has access to which secrets and to identify any unused or over-privileged credentials.
