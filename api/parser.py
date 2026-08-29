import hcl2
from io import StringIO
from fastapi import HTTPException


def _strip_quotes(obj):
    if isinstance(obj, str):
        return obj.strip('"').strip("'")
    elif isinstance(obj, dict):
        return {_strip_quotes(k): _strip_quotes(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_strip_quotes(item) for item in obj]
    return obj


def parse_terraform(file_content: str) -> dict:
    try:
        parsed = hcl2.load(StringIO(file_content))
        return parsed
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to parse Terraform file. Make sure it is valid HCL2 syntax. Error: {str(e)}"
        )


def extract_resources(parsed: dict) -> list[dict]:
    resources = []
    
    # Strip annoying literal quotes from the python-hcl2 output
    clean_parsed = _strip_quotes(parsed)

    for resource_block in clean_parsed.get("resource", []):
        for resource_type, resource_instances in resource_block.items():
            for resource_name, config in resource_instances.items():
                resources.append({
                    "resource_type": resource_type,
                    "resource_name": resource_name,
                    "config": config[0] if isinstance(config, list) else config,
                })

    return resources
