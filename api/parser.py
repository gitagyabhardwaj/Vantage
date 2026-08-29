import hcl2
import json
from io import StringIO
from fastapi import HTTPException


def parse_terraform(file_content: str) -> dict:
    """
    Parses a Terraform (.tf) file content string using python-hcl2.
    Returns a normalized Python dictionary representing all the resources.

    Raises:
        HTTPException 400 if the file cannot be parsed (i.e. not valid HCL).
    """
    try:
        parsed = hcl2.load(StringIO(file_content))
        return parsed
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to parse Terraform file. Make sure it is valid HCL2 syntax. Error: {str(e)}"
        )


def extract_resources(parsed: dict) -> list[dict]:
    """
    Flattens the parsed HCL dictionary into a simple list of resource objects
    so the rule engine can iterate over them easily without worrying about
    nested dictionary structures.

    python-hcl2 produces this structure:
      {
        "resource": [
          {
            "aws_s3_bucket": {
              "my_bucket": { "bucket": "my-data", "acl": "public-read" }
            }
          }
        ]
      }

    This function converts it into a flat list like:
      [
        {
          "resource_type": "aws_s3_bucket",
          "resource_name": "my_bucket",
          "config": { "bucket": "my-data", "acl": "public-read" }
        }
      ]
    """
    resources = []

    # python-hcl2 wraps the "resource" key in a list. We iterate over each item.
    for resource_block in parsed.get("resource", []):
        # Each resource_block is a dict: { "aws_s3_bucket": { "my_bucket": {...} } }
        for resource_type, resource_instances in resource_block.items():
            for resource_name, config in resource_instances.items():
                resources.append({
                    "resource_type": resource_type,
                    "resource_name": resource_name,
                    # config can sometimes be wrapped in a list by hcl2, so we unwrap it
                    "config": config[0] if isinstance(config, list) else config,
                })

    return resources
