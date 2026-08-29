"""
scan_engine.py — Core scan logic extracted so it can be reused
across multiple endpoints (file upload, webhook, chat, etc.)
without duplicating code.
"""

import zipfile
import io
from api.parser import parse_terraform, extract_resources
from api.rules import ALL_RULES
from api.scorer import calculate_score
from api.compliance import enrich_findings


def run_scan(file_content: str, filename: str = "upload.tf") -> dict:
    """
    Takes raw Terraform text, runs the full rule engine,
    and returns a complete scan report dict.
    """
    parsed = parse_terraform(file_content)
    resources = extract_resources(parsed)

    all_findings = []
    for rule_fn in ALL_RULES:
        all_findings.extend(rule_fn(resources))

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

    # Attach compliance framework references to each finding
    enrich_findings(all_findings)

    summary = {
        "critical": sum(1 for f in all_findings if f["severity"] == "CRITICAL"),
        "high":     sum(1 for f in all_findings if f["severity"] == "HIGH"),
        "medium":   sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
        "low":      sum(1 for f in all_findings if f["severity"] == "LOW"),
        "passed":   len(resources) - len(all_findings),
    }

    score_data = calculate_score(all_findings, len(resources))

    # Build dynamic assets map from actual parsed resources
    def get_service_group(res_type: str) -> str:
        if "s3" in res_type or "efs" in res_type:
            return "Storage"
        if "security_group" in res_type or "vpc" in res_type or "route" in res_type:
            return "Network"
        if "iam" in res_type:
            return "Identity"
        if "db" in res_type or "rds" in res_type or "dynamodb" in res_type or "kms" in res_type:
            return "Data"
        if "eks" in res_type or "ecs" in res_type or "instance" in res_type:
            return "Compute"
        return "Infrastructure"

    assets = []
    for r in resources:
        res_full_name = f"{r['resource_type']}.{r['resource_name']}"
        res_findings = [f for f in all_findings if f.get("resource") == res_full_name or r['resource_name'] in f.get("resource", "")]
        
        if res_findings:
            top_severity = res_findings[0]["severity"]
            state = "EXPOSED"
            risk = top_severity
            detail = res_findings[0].get("description", "Security vulnerability detected.")
        else:
            state = "PROTECTED"
            risk = "PASSED"
            detail = "Passed all evaluated security checks."

        # Format a clean HCL representation snippet
        cfg = r.get("config", {})
        props_str = "\n".join([f"  {k} = {repr(v)}" for k, v in list(cfg.items())[:4]]) if isinstance(cfg, dict) else ""
        evidence_snippet = f'resource "{r["resource_type"]}" "{r["resource_name"]}" {{\n{props_str}\n}}'

        assets.append({
            "name": res_full_name,
            "type": r["resource_type"],
            "group": get_service_group(r["resource_type"]),
            "owner": "workspace-owner",
            "state": state,
            "risk": risk,
            "detail": detail,
            "evidence": evidence_snippet,
        })

    return {
        "filename": filename,
        "resources_scanned": len(resources),
        "security_score": score_data,
        "summary": summary,
        "findings": all_findings,
        "assets": assets,
    }


def run_scan_on_zip(zip_bytes: bytes) -> dict:
    """
    Takes raw bytes of a ZIP file, extracts all .tf files inside,
    scans each one, and returns a combined report.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        return {"error": "Invalid ZIP file."}

    tf_files = [name for name in zf.namelist() if name.endswith(".tf")]
    if not tf_files:
        return {"error": "No .tf files found inside the ZIP."}

    # Combine all .tf file contents into one big scan
    combined_content = ""
    file_manifest = []
    for tf_name in tf_files:
        try:
            content = zf.read(tf_name).decode("utf-8")
            combined_content += f"\n# --- File: {tf_name} ---\n{content}\n"
            file_manifest.append(tf_name)
        except Exception:
            continue

    if not combined_content.strip():
        return {"error": "Could not read any .tf files from the ZIP."}

    report = run_scan(combined_content, filename="project.zip")
    report["files_scanned"] = file_manifest
    report["total_files"] = len(file_manifest)
    return report
