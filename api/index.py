import os
import json
from fastapi import FastAPI, UploadFile, File, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx

from api.parser import parse_terraform, extract_resources
from api.rules import ALL_RULES
from api.scan_engine import run_scan, run_scan_on_zip

app = FastAPI(title="Vantage Security Scanner API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── In-memory store for the last scan (used by the AI chat) ─────────────────
# In a real product this would be a database, but for the hackathon demo
# a simple dict works perfectly since only one user is demoing at a time.
last_scan_report: dict = {}


# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINT 1 — Health Check
# ═══════════════════════════════════════════════════════════════════════════════
@app.get("/")
def read_root():
    return {"status": "Vantage Backend is running!"}


# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINT 2 — Scan (Single .tf file OR .zip of a full project)
# ═══════════════════════════════════════════════════════════════════════════════
@app.post("/api/scan")
async def scan_infrastructure(file: UploadFile = File(...)):
    """
    Accepts a single .tf file or a .zip containing multiple .tf files.
    Returns a full security report with score, findings, and compliance mapping.
    """
    global last_scan_report

    filename = file.filename or ""
    raw_bytes = await file.read()

    if filename.endswith(".zip"):
        report = run_scan_on_zip(raw_bytes)
        if "error" in report:
            raise HTTPException(status_code=422, detail=report["error"])
        last_scan_report = report
        return report

    if not filename.endswith(".tf"):
        raise HTTPException(status_code=400, detail="Only .tf and .zip files are supported.")

    try:
        file_content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File encoding error.")

    report = run_scan(file_content, filename)
    if not report.get("resources_scanned"):
        raise HTTPException(status_code=422, detail="No resources found in the Terraform file.")

    last_scan_report = report
    return report


# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINT 3 — AI Auto-Fix (Gemini generates secure Terraform code)
# ═══════════════════════════════════════════════════════════════════════════════
class AiFixRequest(BaseModel):
    resource_type: str
    resource_name: str
    vulnerability_description: str

@app.post("/api/ai-fix")
async def generate_ai_fix(request: AiFixRequest):
    """
    Takes a vulnerable resource and uses Google Gemini to generate the secure Terraform code.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="GEMINI_API_KEY is not set.")

    import google.generativeai as genai
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-2.5-flash")

    prompt = f"""You are an expert cloud security engineer.
I have a Terraform resource of type '{request.resource_type}' named '{request.resource_name}'.
It was flagged with the following security vulnerability:
"{request.vulnerability_description}"

Write the completely secure, fixed Terraform (HCL) block for this resource.
Return ONLY the raw HCL code. Do not include markdown formatting like ```hcl or any explanations."""

    try:
        response = model.generate_content(prompt)
        clean_code = response.text.strip()
        # Strip accidental markdown fences
        if clean_code.startswith("```"):
            clean_code = clean_code.split("\n", 1)[-1]
        if clean_code.endswith("```"):
            clean_code = clean_code.rsplit("```", 1)[0]
        return {"fixed_code": clean_code.strip()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Error: {str(e)}")


# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINT 4 — Chat with your Infrastructure (AI Agent)
# ═══════════════════════════════════════════════════════════════════════════════
class ChatRequest(BaseModel):
    question: str

@app.post("/api/chat")
async def chat_with_infra(request: ChatRequest):
    """
    Lets users ask natural language questions about their scanned infrastructure.
    Uses the last scan report as context for the AI.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="GEMINI_API_KEY is not set.")

    if not last_scan_report:
        raise HTTPException(
            status_code=400,
            detail="No scan data available. Please upload and scan a Terraform file first."
        )

    import google.generativeai as genai
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-2.5-flash")

    # Build a concise context from the scan report
    context = json.dumps({
        "security_score": last_scan_report.get("security_score"),
        "summary": last_scan_report.get("summary"),
        "findings": last_scan_report.get("findings", []),
    }, indent=2)

    prompt = f"""You are Vantage, an expert AI cloud security assistant.
The user has just scanned their Terraform infrastructure. Here is the full scan report:

{context}

The user is now asking you a question about their infrastructure security.
Answer clearly and concisely. If they ask about risks, reference specific resources and rule IDs from the report.
If they ask how to fix something, provide the exact Terraform code fix.

User's question: "{request.question}"
"""

    try:
        response = model.generate_content(prompt)
        return {"answer": response.text.strip()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Error: {str(e)}")


# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINT 5 — GitHub PR Webhook (Automated DevSecOps Bot)
# ═══════════════════════════════════════════════════════════════════════════════
async def process_github_pr(payload: dict):
    """Background task: fetch PR files, scan them, post a comment with results."""
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        print("Error: GITHUB_TOKEN not set.")
        return

    repo_full_name = payload.get("repository", {}).get("full_name")
    pr_number = payload.get("pull_request", {}).get("number")

    if not repo_full_name or not pr_number:
        return

    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
    }

    async with httpx.AsyncClient() as client:
        # 1. Fetch files changed in the PR
        files_url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}/files"
        files_resp = await client.get(files_url, headers=headers)
        if files_resp.status_code != 200:
            print(f"Failed to fetch PR files: {files_resp.text}")
            return

        combined_content = ""
        tf_count = 0

        # 2. Download raw content of each .tf file
        for file_data in files_resp.json():
            filename = file_data.get("filename", "")
            if not filename.endswith(".tf"):
                continue
            raw_url = file_data.get("raw_url")
            if not raw_url:
                continue
            raw_resp = await client.get(raw_url, headers=headers)
            if raw_resp.status_code != 200:
                continue
            combined_content += f"\n# --- {filename} ---\n{raw_resp.text}\n"
            tf_count += 1

        if not combined_content.strip():
            return

        # 3. Run the scan engine
        try:
            report = run_scan(combined_content, filename=f"PR #{pr_number}")
        except Exception as e:
            print(f"Scan failed for PR #{pr_number}: {e}")
            return

        findings = report.get("findings", [])
        score = report.get("security_score", {})

        # 4. Post a PR comment
        if findings:
            grade = score.get("grade", "?")
            numeric = score.get("score", 0)
            critical = report["summary"]["critical"]
            high = report["summary"]["high"]

            body = f"## 🚨 Vantage Security Scan — Grade: {grade} ({numeric}/100)\n\n"
            body += f"Scanned **{tf_count}** Terraform files ({report['resources_scanned']} resources). "
            body += f"Found **{len(findings)}** issues ({critical} Critical, {high} High).\n\n"
            body += "| Severity | Resource | Issue |\n|---|---|---|\n"
            for f in findings[:5]:
                body += f"| **{f['severity']}** | `{f['resource']}` | {f['description'][:80]}... |\n"
            if len(findings) > 5:
                body += f"\n*...and {len(findings) - 5} more. View the full report on your Vantage dashboard.*\n"
            body += "\n⚠️ **Please fix these issues before merging.**"
        else:
            body = f"## ✅ Vantage Security Scan Passed — Grade: {score.get('grade', 'A+')} ({score.get('score', 100)}/100)\n\n"
            body += f"Scanned **{tf_count}** Terraform files ({report['resources_scanned']} resources). No vulnerabilities found. Ship it! 🚀"

        comment_url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
        await client.post(comment_url, headers=headers, json={"body": body})


@app.post("/api/webhook")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Receives webhook events from GitHub.
    Returns 200 OK immediately and processes the PR scan in the background.
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    action = payload.get("action")
    if action in ["opened", "synchronize"] and "pull_request" in payload:
        background_tasks.add_task(process_github_pr, payload)
        return {"status": "Scan queued"}

    return {"status": "Ignored"}
