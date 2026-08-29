# 🚨 Scanner Security Rules

This document outlines the specific security rules the **CloudGuard** engine will check for when analyzing Terraform files. 

For the hackathon, we are implementing **5 high-impact, easily demonstrable rules**. This shows the judges we understand real-world cloud security without over-complicating the 10-hour build.

---

### Rule 1: Publicly Accessible S3 Bucket
**Severity:** 🔴 CRITICAL
**Why it matters:** The #1 cause of cloud data breaches. S3 buckets should never be public unless explicitly hosting public website assets.
**Detection Logic (Terraform):**
*   **Resource:** `aws_s3_bucket`
*   **Trigger:** Check if the attribute `acl` is set to `"public-read"` or `"public-read-write"`.
**Actionable Insight (Remediation):**
```hcl
# Change this:
acl = "public-read"
# To this:
acl = "private"
```

---

### Rule 2: Open SSH Access (Security Group)
**Severity:** 🔴 CRITICAL
**Why it matters:** Allowing SSH (Port 22) access from anywhere (`0.0.0.0/0`) exposes servers to brute-force attacks from the entire internet.
**Detection Logic (Terraform):**
*   **Resource:** `aws_security_group` or `aws_security_group_rule`
*   **Trigger:** Check `ingress` blocks where `from_port == 22` AND `to_port == 22` AND `cidr_blocks` contains `"0.0.0.0/0"`.
**Actionable Insight (Remediation):**
```hcl
# Restrict CIDR block to your VPN or IP address:
cidr_blocks = ["203.0.113.0/32"] # Replace 0.0.0.0/0
```

---

### Rule 3: Overly Permissive IAM Policy
**Severity:** 🟠 HIGH
**Why it matters:** "Star/Star" (`*/*`) permissions grant absolute administrative control. If these credentials leak, the attacker owns the entire AWS account.
**Detection Logic (Terraform):**
*   **Resource:** `aws_iam_policy` (Specifically looking inside the `policy` JSON block)
*   **Trigger:** Check if the Statement contains `"Action": "*"` AND `"Resource": "*"`.
**Actionable Insight (Remediation):**
```json
// Apply the Principle of Least Privilege by specifying exact actions and resources.
"Action": [
  "s3:GetObject",
  "s3:ListBucket"
],
"Resource": "arn:aws:s3:::my-secure-bucket/*"
```

---

### Rule 4: Unencrypted Database (RDS)
**Severity:** 🟠 HIGH
**Why it matters:** If the underlying database storage is not encrypted at rest, physical access to the server or snapshots could result in a data breach.
**Detection Logic (Terraform):**
*   **Resource:** `aws_db_instance`
*   **Trigger:** Check if `storage_encrypted` is missing, or set to `false`.
**Actionable Insight (Remediation):**
```hcl
# Add the following line to your aws_db_instance block:
storage_encrypted = true
```

---

### Rule 5: Missing S3 Bucket Versioning
**Severity:** 🟡 MEDIUM
**Why it matters:** Versioning protects against accidental deletion and ransomware attacks (which overwrite files).
**Detection Logic (Terraform):**
*   **Resource:** `aws_s3_bucket_versioning`
*   **Trigger:** Check if `status` is missing, or set to `"Suspended"`.
**Actionable Insight (Remediation):**
```hcl
# Add a versioning configuration block:
versioning_configuration {
  status = "Enabled"
}
```

---

## 🛠️ How the Engine Will Process These

When the Python backend receives a `.tf` file, it uses `python-hcl2` to convert it to a standard Python dictionary.

A vulnerable S3 bucket looks like this in Terraform:
```hcl
resource "aws_s3_bucket" "my_data" {
  bucket = "company-sensitive-data"
  acl    = "public-read"
}
```

Our Python code will parse it into this, making it incredibly easy to write `if/else` rules against:
```python
{
  "resource": [
    {
      "aws_s3_bucket": {
        "my_data": {
          "bucket": "company-sensitive-data",
          "acl": "public-read"  # <-- Our Rule 1 catches this exactly here!
        }
      }
    }
  ]
}
```
