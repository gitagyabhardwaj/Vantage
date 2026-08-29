from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Vantage Security Scanner API")

# Enable CORS so the React frontend can talk to this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For a hackathon, we keep this wide open to avoid localhost port issues
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
    Accepts a Terraform (.tf) file and returns a security scan report.
    NOTE: Currently returning mock data to unblock frontend development.
    """
    
    # We will replace this with python-hcl2 parsing in Step 2.
    # For now, we return the agreed-upon JSON contract so the frontend can build the UI.
    return {
        "summary": {
            "critical": 1,
            "high": 1,
            "medium": 0,
            "passed": 15
        },
        "findings": [
            {
                "rule_id": "AWS-001",
                "severity": "CRITICAL",
                "resource": "aws_s3_bucket.main",
                "description": "S3 bucket allows public read access.",
                "remediation": "Change `acl = \"public-read\"` to `acl = \"private\"`."
            },
            {
                "rule_id": "AWS-003",
                "severity": "HIGH",
                "resource": "aws_iam_policy.admin",
                "description": "IAM Policy grants * (Star) permissions.",
                "remediation": "Specify exact actions instead of `\"Action\": \"*\"`."
            }
        ]
    }
