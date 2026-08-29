# 🛡️ CloudGuard: Infrastructure Security Scanner

> **Hackathon Problem Statement:** Create a tool that scans cloud-based environments for security vulnerabilities — such as misconfigured permissions and exposed data — and provides actionable insights to help businesses strengthen their cloud security.

## 🎯 The Strategy
Instead of attempting complex live-cloud API integrations (which require managing AWS credentials during a demo), **CloudGuard** is designed as a **Static Infrastructure-as-Code (IaC) Scanner**. 

It analyzes Terraform (`.tf`) files before they are deployed, catching misconfigurations at the code level. This guarantees a flawless demo, requires zero cloud credentials, and solves a massive real-world problem (shifting security "left").

## 🏗️ Architecture & Tech Stack

For a 10-hour hackathon, we are prioritizing speed, visual impact, and simplicity.

*   **Frontend (The "Wow" Factor):** React.js + Tailwind CSS + Vite
    *   *Why:* Beautiful, fast, and easy to build dashboard components.
    *   *Key UI:* File drag-and-drop, severity charts (Donut chart for Critical/High/Medium), expandable list of findings, and code blocks showing exactly how to fix the issue.
*   **Backend (The Brains):** Python + FastAPI
    *   *Why:* Python is perfect for text parsing and rule evaluation.
    *   *Parser:* `python-hcl2` library (translates Terraform `.tf` files into easy-to-read JSON dictionaries).
*   **Demo Assets:** Pre-written vulnerable `.tf` files to upload during the pitch.

## 🚀 The 10-Hour Roadmap

### Phase 1: Core Engine (Hours 1-3)
- [ ] Set up Python FastAPI backend.
- [ ] Integrate `python-hcl2` to parse uploaded `.tf` files into JSON.
- [ ] Build the Rule Engine: A function that iterates over the parsed JSON and checks it against our predefined security rules (see `Scanner_Security_Rules.md`).

### Phase 2: API & Data Formatting (Hours 4-5)
- [ ] Create the `/scan` endpoint.
- [ ] Format the output into a standardized JSON response containing:
  - Severity Level
  - Resource Name
  - Vulnerability Description
  - Remediation Snippet (The actionable insight)

### Phase 3: Frontend Dashboard (Hours 6-9)
- [ ] Setup React + Vite + Tailwind.
- [ ] Build the drag-and-drop file upload zone.
- [ ] Build the "Scan Results" dashboard (Stats overview + Findings list).
- [ ] Style the remediation blocks to look like code editors.

### Phase 4: Polish & Pitch Prep (Hour 10)
- [ ] Create 3 "Demo Scenarios" (e.g., `demo_critical.tf`, `demo_clean.tf`).
- [ ] Write the pitch emphasizing *Actionable Insights* and *Developer-First Security*.

## 📡 API Specification (Draft)

**`POST /api/scan`**
*Content-Type: multipart/form-data (file upload)*

**Response:**
```json
{
  "summary": {
    "critical": 1,
    "high": 2,
    "medium": 0,
    "passed": 12
  },
  "findings": [
    {
      "rule_id": "AWS-001",
      "severity": "CRITICAL",
      "resource": "aws_s3_bucket.main",
      "description": "S3 bucket allows public read access.",
      "remediation": "Change `acl = \"public-read\"` to `acl = \"private\"`."
    }
  ]
}
```
