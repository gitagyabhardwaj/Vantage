"""
compliance.py — Maps each Vantage rule to real-world compliance frameworks.

This enriches findings with the exact industry standards they violate,
so enterprises can use our reports for audit evidence.
"""

# Each rule_id maps to a list of compliance references
COMPLIANCE_MAP = {
    "AWS-001": [
        {"framework": "CIS AWS", "control": "2.1.1", "title": "Ensure S3 Bucket Policy does not grant public access"},
        {"framework": "PCI-DSS", "control": "3.4", "title": "Render PAN unreadable anywhere it is stored"},
        {"framework": "SOC 2", "control": "CC6.1", "title": "Logical and Physical Access Controls"},
    ],
    "AWS-002": [
        {"framework": "CIS AWS", "control": "5.2", "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"},
        {"framework": "PCI-DSS", "control": "1.3.1", "title": "Restrict inbound traffic to only necessary protocols"},
        {"framework": "HIPAA", "control": "164.312(e)(1)", "title": "Transmission Security"},
    ],
    "AWS-003": [
        {"framework": "CIS AWS", "control": "1.22", "title": "Ensure IAM policies that allow full '*:*' are not attached"},
        {"framework": "SOC 2", "control": "CC6.3", "title": "Role-Based Access and Least Privilege"},
        {"framework": "NIST 800-53", "control": "AC-6", "title": "Least Privilege"},
    ],
    "AWS-004": [
        {"framework": "CIS AWS", "control": "2.3.1", "title": "Ensure RDS instances have encryption at rest enabled"},
        {"framework": "PCI-DSS", "control": "3.4", "title": "Render PAN unreadable anywhere it is stored"},
        {"framework": "HIPAA", "control": "164.312(a)(2)(iv)", "title": "Encryption and Decryption"},
    ],
    "AWS-005": [
        {"framework": "CIS AWS", "control": "2.1.3", "title": "Ensure S3 versioning is enabled"},
        {"framework": "SOC 2", "control": "A1.2", "title": "Recovery and Resilience"},
        {"framework": "NIST 800-53", "control": "CP-9", "title": "Information System Backup"},
    ],
    "AWS-006": [
        {"framework": "CIS AWS", "control": "5.1", "title": "Ensure no EC2 instances have public IPs"},
        {"framework": "NIST 800-53", "control": "SC-7", "title": "Boundary Protection"},
    ],
    "AWS-007": [
        {"framework": "CIS AWS", "control": "5.3", "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389"},
        {"framework": "PCI-DSS", "control": "1.3.1", "title": "Restrict inbound traffic"},
        {"framework": "HIPAA", "control": "164.312(e)(1)", "title": "Transmission Security"},
    ],
    "AWS-008": [
        {"framework": "CIS AWS", "control": "2.2.1", "title": "Ensure EBS volume encryption is enabled"},
        {"framework": "PCI-DSS", "control": "3.4", "title": "Render PAN unreadable anywhere it is stored"},
        {"framework": "HIPAA", "control": "164.312(a)(2)(iv)", "title": "Encryption and Decryption"},
    ],
    "AWS-009": [
        {"framework": "CIS AWS", "control": "7.1", "title": "Ensure Image Vulnerability Scanning is enabled"},
        {"framework": "SOC 2", "control": "CC7.1", "title": "Manage Vulnerabilities"},
    ],
    "AWS-010": [
        {"framework": "CIS AWS", "control": "2.4", "title": "Ensure SQS queues are encrypted"},
        {"framework": "PCI-DSS", "control": "4.1", "title": "Use strong cryptography for transmission"},
    ],
    "AWS-011": [
        {"framework": "CIS AWS", "control": "2.3.2", "title": "Ensure RDS instances are not publicly accessible"},
        {"framework": "PCI-DSS", "control": "1.2.1", "title": "Restrict connections to untrusted networks"},
        {"framework": "HIPAA", "control": "164.312(e)(1)", "title": "Transmission Security"},
    ],
    "AWS-012": [
        {"framework": "CIS AWS", "control": "3.1", "title": "Ensure CloudTrail is enabled in all regions"},
        {"framework": "SOC 2", "control": "CC7.2", "title": "Monitor System Components for Anomalies"},
        {"framework": "NIST 800-53", "control": "AU-2", "title": "Audit Events"},
    ],
    "AWS-013": [
        {"framework": "CIS AWS", "control": "2.8", "title": "Ensure rotation for customer-created KMS keys is enabled"},
        {"framework": "PCI-DSS", "control": "3.6.4", "title": "Cryptographic key changes for keys past crypto-period"},
        {"framework": "NIST 800-53", "control": "SC-12", "title": "Cryptographic Key Management"},
    ],
    "AWS-014": [
        {"framework": "CIS AWS", "control": "5.7", "title": "Ensure ALB drops invalid HTTP headers"},
        {"framework": "NIST 800-53", "control": "SC-7", "title": "Boundary Protection"},
    ],
    "AWS-015": [
        {"framework": "CIS AWS", "control": "3.11", "title": "Ensure API Gateway has X-Ray tracing enabled"},
        {"framework": "SOC 2", "control": "CC7.2", "title": "Monitor System Components"},
    ],
}


def enrich_findings(findings: list[dict]) -> list[dict]:
    """
    Takes a list of findings and attaches the relevant compliance
    framework references to each one.
    """
    for finding in findings:
        rule_id = finding.get("rule_id", "")
        finding["compliance"] = COMPLIANCE_MAP.get(rule_id, [])
    return findings
