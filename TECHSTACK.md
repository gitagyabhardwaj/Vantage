# 🛠️ Vantage: Tech Stack & Architecture

To build a high-performance, visually impressive Cloud Security Scanner in just 10 hours, we selected a highly decoupled, modern tech stack. 

This stack allows the frontend and backend teams to work entirely in parallel using an agreed-upon JSON API contract.

## 🧑‍💻 The Backend Engine
**Primary language:** Python 3.10+
**Framework:** FastAPI

*   **FastAPI:** Chosen for its incredible speed, out-of-the-box async support, and automatic Swagger documentation. It allows us to spin up REST endpoints in seconds.
*   **python-hcl2:** The secret sauce for this hackathon. Instead of writing complex regex to parse Terraform, this library cleanly converts HashiCorp Configuration Language (`.tf` files) directly into native Python dictionaries, making our rule engine logic extremely simple.
*   **python-multipart:** Required by FastAPI to handle file uploads via `multipart/form-data`.
*   **Uvicorn:** The lightning-fast ASGI server that runs our FastAPI application.

## 🎨 The Frontend Dashboard
**Primary language:** JavaScript / TypeScript
**Framework:** React (via Vite)

*   **Vite:** Replaces Create React App (CRA). It offers instant server start and lightning-fast HMR (Hot Module Replacement), which is crucial for moving quickly during a hackathon.
*   **Tailwind CSS:** Allows for rapid UI prototyping without writing custom CSS files. Perfect for building clean, enterprise-looking security dashboards.
*   **Lucide React:** A clean, modern icon library for our severity badges and UI elements.
*   **Axios / Fetch:** Used to communicate with the Python backend via the `/api/scan` endpoint.

## 🌉 The API Contract
The bridge between the two stacks. The backend guarantees it will always return data in this shape, allowing the frontend to use Mock JSON to build the UI before the backend engine is completely finished:

```json
{
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
    }
  ]
}
```
