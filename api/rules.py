"""
rules.py — The Security Rule Engine for Vantage.

Each function takes the flat list of resource objects (produced by parser.py)
and returns a list of findings (empty list = no violations found for that rule).

A finding always has this shape:
{
    "rule_id":    str   — e.g. "AWS-001"
    "severity":   str   — "CRITICAL" | "HIGH" | "MEDIUM"
    "resource":   str   — e.g. "aws_s3_bucket.my_bucket"
    "description": str  — plain-english explanation of the problem
    "remediation": str  — exact fix the developer should apply
}
"""

from typing import Any


def _resource_label(r: dict) -> str:
    """Helper: returns 'resource_type.resource_name' label for a resource."""
    return f"{r['resource_type']}.{r['resource_name']}"


def _get(config: dict, *keys: str, default: Any = None) -> Any:
    """
    Safely traverse a nested dict by a sequence of keys.
    Returns `default` if any key is missing.
    """
    val = config
    for key in keys:
        if not isinstance(val, dict):
            return default
        val = val.get(key, default)
        if val is None:
            return default
    return val


# ──────────────────────────────────────────────────────────────────────────────
# RULE AWS-001 — S3 Bucket: Public ACL
# Severity: CRITICAL
# ──────────────────────────────────────────────────────────────────────────────
def check_s3_public_acl(resources: list[dict]) -> list[dict]:
    """
    Flags any aws_s3_bucket whose `acl` attribute is set to a public value.
    Public ACLs like 'public-read' or 'public-read-write' expose bucket
    contents to the entire internet — the #1 cause of cloud data breaches.
    """
    findings = []
    PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}

    for r in resources:
        if r["resource_type"] != "aws_s3_bucket":
            continue

        acl = r["config"].get("acl", "private")
        # acl can be wrapped in a list by hcl2
        if isinstance(acl, list):
            acl = acl[0]

        if str(acl).lower() in PUBLIC_ACLS:
            findings.append({
                "rule_id": "AWS-001",
                "severity": "CRITICAL",
                "resource": _resource_label(r),
                "description": (
                    f"S3 bucket is publicly accessible via ACL `{acl}`. "
                    "This exposes all objects in the bucket to the internet."
                ),
                "remediation": (
                    "Set `acl = \"private\"` and use bucket policies to grant "
                    "explicit, scoped access to only the principals that need it."
                ),
            })

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# RULE AWS-002 — Security Group: Open SSH (Port 22) to the World
# Severity: CRITICAL
# ──────────────────────────────────────────────────────────────────────────────
def check_open_ssh(resources: list[dict]) -> list[dict]:
    """
    Flags aws_security_group resources that allow unrestricted inbound SSH
    (port 22) from 0.0.0.0/0 or ::/0, exposing instances to brute-force attacks
    from anywhere on the internet.
    """
    findings = []
    OPEN_CIDRS = {"0.0.0.0/0", "::/0"}

    for r in resources:
        if r["resource_type"] not in ("aws_security_group", "aws_security_group_rule"):
            continue

        ingress_rules = r["config"].get("ingress", [])
        if not isinstance(ingress_rules, list):
            ingress_rules = [ingress_rules]

        for rule in ingress_rules:
            if not isinstance(rule, dict):
                continue

            from_port = rule.get("from_port", -1)
            to_port = rule.get("to_port", -1)

            # Unwrap if hcl2 wrapped in list
            if isinstance(from_port, list): from_port = from_port[0]
            if isinstance(to_port, list):   to_port   = to_port[0]

            cidr_blocks = rule.get("cidr_blocks", []) or []
            ipv6_cidr   = rule.get("ipv6_cidr_blocks", []) or []
            if isinstance(cidr_blocks, list) is False: cidr_blocks = [cidr_blocks]
            if isinstance(ipv6_cidr, list) is False:   ipv6_cidr   = [ipv6_cidr]

            all_cidrs = set(cidr_blocks) | set(ipv6_cidr)
            open_to_world = bool(all_cidrs & OPEN_CIDRS)

            try:
                port_22_exposed = int(from_port) <= 22 <= int(to_port)
            except (TypeError, ValueError):
                port_22_exposed = False

            if port_22_exposed and open_to_world:
                findings.append({
                    "rule_id": "AWS-002",
                    "severity": "CRITICAL",
                    "resource": _resource_label(r),
                    "description": (
                        "Security group allows unrestricted inbound SSH access (port 22) "
                        "from the entire internet (0.0.0.0/0 or ::/0). "
                        "This exposes your instances to brute-force and credential-stuffing attacks."
                    ),
                    "remediation": (
                        "Restrict the SSH CIDR block to your specific IP address or VPN CIDR, "
                        "e.g. `cidr_blocks = [\"YOUR_IP/32\"]`. "
                        "Consider using AWS Systems Manager Session Manager instead of direct SSH."
                    ),
                })

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# RULE AWS-003 — IAM Policy: Wildcard Star/Star Permissions
# Severity: HIGH
# ──────────────────────────────────────────────────────────────────────────────
def check_iam_wildcard(resources: list[dict]) -> list[dict]:
    """
    Flags aws_iam_policy resources whose policy JSON document contains a
    Statement with both `Action: '*'` and `Resource: '*'` — the equivalent of
    granting full administrator access to any principal that assumes this policy.
    """
    import json as _json

    findings = []

    for r in resources:
        if r["resource_type"] not in ("aws_iam_policy", "aws_iam_role_policy"):
            continue

        policy_raw = r["config"].get("policy")
        if policy_raw is None:
            continue
        if isinstance(policy_raw, list):
            policy_raw = policy_raw[0]

        # policy can be a JSON string or already a dict (depends on hcl2 version)
        if isinstance(policy_raw, str):
            try:
                policy_doc = _json.loads(policy_raw)
            except _json.JSONDecodeError:
                continue
        elif isinstance(policy_raw, dict):
            policy_doc = policy_raw
        else:
            continue

        statements = policy_doc.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        for stmt in statements:
            action   = stmt.get("Action", "")
            resource = stmt.get("Resource", "")
            effect   = stmt.get("Effect", "Allow")

            # Normalise to lists for uniform comparison
            if isinstance(action, str):   action   = [action]
            if isinstance(resource, str): resource = [resource]

            if effect == "Allow" and "*" in action and "*" in resource:
                findings.append({
                    "rule_id": "AWS-003",
                    "severity": "HIGH",
                    "resource": _resource_label(r),
                    "description": (
                        "IAM policy grants `Action: '*'` on `Resource: '*'`. "
                        "This is full administrator access — if these credentials are "
                        "leaked, an attacker gains complete control of the AWS account."
                    ),
                    "remediation": (
                        "Apply the Principle of Least Privilege: specify only the exact "
                        "actions your application needs (e.g. `s3:GetObject`, `s3:PutObject`) "
                        "and scope `Resource` to the specific ARNs required."
                    ),
                })

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# RULE AWS-004 — RDS Instance: Unencrypted Storage at Rest
# Severity: HIGH
# ──────────────────────────────────────────────────────────────────────────────
def check_rds_unencrypted(resources: list[dict]) -> list[dict]:
    """
    Flags aws_db_instance resources where `storage_encrypted` is either
    missing or explicitly set to false. Unencrypted RDS instances mean that
    database snapshots, backups, and disk access could expose raw data.
    """
    findings = []

    for r in resources:
        if r["resource_type"] != "aws_db_instance":
            continue

        encrypted = r["config"].get("storage_encrypted", False)
        if isinstance(encrypted, list):
            encrypted = encrypted[0]

        # Treat missing key (False default) or explicit False as a violation
        if str(encrypted).lower() in ("false", "0", "no", ""):
            findings.append({
                "rule_id": "AWS-004",
                "severity": "HIGH",
                "resource": _resource_label(r),
                "description": (
                    "RDS database instance does not have storage encryption enabled. "
                    "Database snapshots and automated backups will also be unencrypted, "
                    "putting data at rest at risk."
                ),
                "remediation": (
                    "Add `storage_encrypted = true` to your `aws_db_instance` resource. "
                    "Note: encryption cannot be enabled on an existing unencrypted instance — "
                    "you will need to create a new encrypted instance and migrate the data."
                ),
            })

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# RULE AWS-005 — S3 Bucket: Versioning Not Enabled
# Severity: MEDIUM
# ──────────────────────────────────────────────────────────────────────────────
def check_s3_versioning_disabled(resources: list[dict]) -> list[dict]:
    """
    Flags aws_s3_bucket_versioning resources where versioning status is
    Suspended or missing. Without versioning, objects accidentally deleted or
    overwritten (e.g. by ransomware) cannot be recovered.
    """
    findings = []

    # Track which bucket IDs have versioning configured and enabled
    versioning_enabled_buckets = set()
    versioning_resources = []

    for r in resources:
        if r["resource_type"] == "aws_s3_bucket_versioning":
            versioning_resources.append(r)

    for r in versioning_resources:
        bucket_ref = r["config"].get("bucket")
        if isinstance(bucket_ref, list): bucket_ref = bucket_ref[0]

        versioning_conf = r["config"].get("versioning_configuration", {})
        if isinstance(versioning_conf, list): versioning_conf = versioning_conf[0]

        status = versioning_conf.get("status", "Suspended") if isinstance(versioning_conf, dict) else "Suspended"
        if isinstance(status, list): status = status[0]

        if str(status).lower() == "enabled":
            versioning_enabled_buckets.add(bucket_ref)
        else:
            findings.append({
                "rule_id": "AWS-005",
                "severity": "MEDIUM",
                "resource": _resource_label(r),
                "description": (
                    f"S3 bucket versioning is `{status}`. "
                    "Without versioning, objects that are accidentally deleted or "
                    "overwritten by ransomware cannot be recovered."
                ),
                "remediation": (
                    "Set `status = \"Enabled\"` inside the `versioning_configuration` block "
                    "of your `aws_s3_bucket_versioning` resource."
                ),
            })

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Master runner — called by the engine
# ──────────────────────────────────────────────────────────────────────────────
ALL_RULES = [
    check_s3_public_acl,
    check_open_ssh,
    check_iam_wildcard,
    check_rds_unencrypted,
    check_s3_versioning_disabled,
    check_ec2_public_ip,
    check_open_rdp,
    check_ebs_unencrypted,
    check_ecr_scanning_disabled,
    check_sqs_unencrypted,
    check_rds_public,
    check_cloudtrail_multi_region,
    check_kms_rotation,
    check_alb_headers,
    check_apigw_tracing,
    check_efs_unencrypted,
    check_elasticache_transit,
    check_elasticache_at_rest,
    check_cloudfront_allow_http,
    check_sagemaker_root_access,
    check_docdb_unencrypted,
    check_dax_unencrypted,
    check_kinesis_unencrypted,
    check_redshift_public,
    check_redshift_unencrypted,
    check_eks_public_endpoint,
    check_emr_unencrypted,
    check_mq_public,
    check_neptune_unencrypted,
    check_workspace_unencrypted,
    check_athena_unencrypted,
    check_sns_unencrypted,
    check_ecs_no_transit_encryption,
    check_codebuild_unencrypted,
    check_appsync_waf_disabled,
    check_apigateway_waf_disabled,
    check_lambda_tracing_disabled,
    check_vpc_flow_logs_disabled,
    check_iam_password_reuse,
    check_iam_password_length,
    check_s3_block_public_acls,
    check_s3_ignore_public_acls,
    check_s3_block_public_policy,
    check_s3_restrict_public_buckets,
    check_dynamodb_pitr_disabled,
]
