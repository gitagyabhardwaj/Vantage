import os
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import google.generativeai as genai

from api.parser import parse_terraform, extract_resources
from api.rules import ALL_RULES

app = FastAPI(title="Vantage Security Scanner API")

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
    if not file.filename.endswith(".tf"):
        raise HTTPException(status_code=400, detail="Only Terraform (.tf) files are supported.")

    raw_bytes = await file.read()
    try:
        file_content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File encoding error.")

    parsed = parse_terraform(file_content)
    resources = extract_resources(parsed)

    if not resources:
        raise HTTPException(status_code=422, detail="No resources found in the Terraform file.")

    all_findings = []
    for rule_fn in ALL_RULES:
        all_findings.extend(rule_fn(resources))

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    all_findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

    summary = {
        "critical": sum(1 for f in all_findings if f["severity"] == "CRITICAL"),
        "high":     sum(1 for f in all_findings if f["severity"] == "HIGH"),
        "medium":   sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
        "passed":   len(resources) - len(all_findings),
    }

    return {
        "filename": file.filename,
        "resources_scanned": len(resources),
        "summary": summary,
        "findings": all_findings,
    }


class AiFixRequest(BaseModel):
    resource_type: str
    resource_name: str
    vulnerability_description: str

@app.post("/api/ai-fix")
async def generate_ai_fix(request: AiFixRequest):
    """
    Takes a vulnerable resource and uses Google Gemini to generate the secure Terraform code.
    Requires GEMINI_API_KEY environment variable.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=500, 
            detail="GEMINI_API_KEY environment variable is missing. Keep it safe in Vercel settings!"
        )
    
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-1.5-flash')
    
    prompt = f"""
    You are an expert cloud security engineer. 
    I have a Terraform resource of type '{request.resource_type}' named '{request.resource_name}'.
    It was flagged with the following security vulnerability: 
    "{request.vulnerability_description}"
    
    Write the completely secure, fixed Terraform (HCL) block for this resource.
    Return ONLY the raw HCL code. Do not include markdown formatting like ```hcl or any explanations.
    """
    
    try:
        response = model.generate_content(prompt)
        # Strip any accidental markdown blocks the LLM might include despite instructions
        clean_code = response.text.strip().removeprefix("```hcl").removeprefix("```").removesuffix("```").strip()
        return {"fixed_code": clean_code}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Error: {str(e)}")
