from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from api.parser import parse_terraform, extract_resources
from api.rules import ALL_RULES

app = FastAPI(title="Vantage Security Scanner API")

# Enable CORS so the React frontend can talk to this API from any origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"status": "Vantage Backend is running!"}


@app.post("/api/scan")
async def scan_infrastructure(file: UploadFile = File(...)):
    """
    Accepts a Terraform (.tf) file upload and returns a full security scan report.

    Steps:
      1. Read the raw file content.
      2. Validate it's a .tf file.
      3. Parse it with python-hcl2.
      4. Flatten the parsed data into a list of resources.
      5. Run all security rules against each resource.
      6. Aggregate findings and return a structured response.
    """

    # ── Step 1: Validate file type ────────────────────────────────────────────
    if not file.filename.endswith(".tf"):
        raise HTTPException(
            status_code=400,
            detail="Only Terraform (.tf) files are supported. Please upload a valid .tf file."
        )

    # ── Step 2: Read file content ─────────────────────────────────────────────
    raw_bytes = await file.read()
    try:
        file_content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="File encoding error. Please ensure the file is UTF-8 encoded."
        )

    # ── Step 3: Parse the Terraform file ─────────────────────────────────────
    parsed = parse_terraform(file_content)

    # ── Step 4: Flatten resources ─────────────────────────────────────────────
    resources = extract_resources(parsed)

    if not resources:
        raise HTTPException(
            status_code=422,
            detail="No resources found in the Terraform file. Make sure it contains at least one `resource` block."
        )

    # ── Step 5: Run all security rules ────────────────────────────────────────
    all_findings = []
    for rule_fn in ALL_RULES:
        all_findings.extend(rule_fn(resources))

    # ── Step 6: Build the response ────────────────────────────────────────────
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    all_findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

    summary = {
        "critical": sum(1 for f in all_findings if f["severity"] == "CRITICAL"),
        "high":     sum(1 for f in all_findings if f["severity"] == "HIGH"),
        "medium":   sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
        # "passed" = total resources that didn't produce any finding
        "passed":   len(resources) - len(all_findings),
    }

    return {
        "filename": file.filename,
        "resources_scanned": len(resources),
        "summary": summary,
        "findings": all_findings,
    }
