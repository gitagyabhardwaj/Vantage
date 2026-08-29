"""
scorer.py — Security Score Calculator for Vantage.

Calculates a 0-100 "Security Score" (like a credit score for your cloud)
and assigns a letter grade (A-F). This gives the frontend a single,
glanceable metric to display on the dashboard.
"""

# Weights: how many points each severity deducts per finding
SEVERITY_WEIGHTS = {
    "CRITICAL": 15,
    "HIGH": 8,
    "MEDIUM": 4,
    "LOW": 2,
}


def calculate_score(findings: list[dict], total_resources: int) -> dict:
    """
    Takes the list of findings and total resource count,
    returns a score object with numeric score, letter grade,
    and a plain-english verdict.
    """
    if total_resources == 0:
        return {"score": 100, "grade": "A+", "verdict": "No resources to scan."}

    # Start at 100, deduct points for each finding
    penalty = 0
    for f in findings:
        penalty += SEVERITY_WEIGHTS.get(f.get("severity", "LOW"), 2)

    # Scale penalty relative to the number of resources so a 500-resource
    # file with 1 medium finding doesn't tank the score unfairly
    scaled_penalty = penalty * (10 / max(total_resources, 1))
    score = max(0, round(100 - scaled_penalty))

    # Letter grade
    if score >= 95:
        grade, verdict = "A+", "Excellent. Your infrastructure follows best practices."
    elif score >= 85:
        grade, verdict = "A", "Strong. Only minor improvements needed."
    elif score >= 75:
        grade, verdict = "B", "Good, but some notable risks should be addressed."
    elif score >= 60:
        grade, verdict = "C", "Fair. Several security gaps need attention."
    elif score >= 40:
        grade, verdict = "D", "Poor. Significant vulnerabilities detected."
    else:
        grade, verdict = "F", "Critical. Immediate remediation required."

    return {
        "score": score,
        "grade": grade,
        "verdict": verdict,
    }
