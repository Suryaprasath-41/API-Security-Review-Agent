import json
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class OpenAPIParser:
    """
    Parses OpenAPI 2.0 (Swagger) and 3.0+ specifications in JSON or YAML formats.
    Attempts to resolve internal references ($ref) dynamically.
    """
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.raw_dict = self._load_file()
        self.resolved_dict = self._resolve_references(self.raw_dict)

    def _load_file(self) -> Dict[str, Any]:
        """Loads JSON or YAML data from the file path and validates OpenAPI schemas."""
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")
        
        content = self.file_path.read_text(encoding="utf-8")
        data = None
        
        # Try parsing as JSON first
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            pass
            
        # Fallback to YAML if JSON fails
        if data is None:
            try:
                data = yaml.safe_load(content)
            except Exception as e:
                raise ValueError(f"Failed to parse specification. Ensure it is valid JSON or YAML. Details: {e}")

        # Ensure the content is a JSON object / YAML dictionary
        if not isinstance(data, dict):
            raise ValueError("Invalid format. The specification must be a dictionary representation (JSON/YAML object).")

        # Validate that the file is an OpenAPI/Swagger contract
        is_openapi_contract = "openapi" in data or "swagger" in data or "paths" in data
        if not is_openapi_contract:
            raise ValueError(
                "The file is a valid JSON/YAML document but does not appear to be an OpenAPI/Swagger specification. "
                "The file must define an 'openapi', 'swagger', or 'paths' mapping."
            )
            
        return data

    def _resolve_references(self, obj: Any, root_obj: Dict[str, Any] = None) -> Any:
        """
        Recursively resolves local JSON references (e.g. #/components/schemas/User).
        Does not support remote/external URLs to avoid network dependency.
        """
        if root_obj is None:
            root_obj = obj

        if isinstance(obj, dict):
            if "$ref" in obj:
                ref_path = obj["$ref"]
                if isinstance(ref_path, str) and ref_path.startswith("#/"):
                    resolved = self._get_by_path(root_obj, ref_path.lstrip("#/").split("/"))
                    if resolved is not None:
                        # Copy properties other than $ref into the resolved dict if applicable
                        merged = resolved.copy() if isinstance(resolved, dict) else resolved
                        for k, v in obj.items():
                            if k != "$ref" and isinstance(merged, dict):
                                merged[k] = v
                        return self._resolve_references(merged, root_obj)
                # If cannot resolve, return as is
                return obj
            else:
                return {k: self._resolve_references(v, root_obj) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._resolve_references(item, root_obj) for item in obj]
        return obj

    def _get_by_path(self, obj: Dict[str, Any], path_parts: List[str]) -> Any:
        """Retrieves a nested object property by list of keys."""
        current = obj
        for part in path_parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(current, list) and part.isdigit():
                idx = int(part)
                if idx < len(current):
                    current = current[idx]
                else:
                    return None
            else:
                return None
        return current

    def get_info(self) -> Dict[str, Any]:
        """Returns API info block metadata."""
        info = self.resolved_dict.get("info", {})
        return {
            "title": info.get("title", "Unknown API"),
            "version": info.get("version", "1.0.0"),
            "description": info.get("description", ""),
            "openapi_version": self.resolved_dict.get("openapi", self.resolved_dict.get("swagger", "unknown"))
        }

    def get_servers(self) -> List[str]:
        """Returns the list of base URLs/servers configured in the specification."""
        servers = []
        if "servers" in self.resolved_dict:
            servers = [s.get("url", "") for s in self.resolved_dict["servers"] if s.get("url")]
        elif "host" in self.resolved_dict:
            base_path = self.resolved_dict.get("basePath", "")
            schemes = self.resolved_dict.get("schemes", ["http"])
            host = self.resolved_dict["host"]
            servers = [f"{scheme}://{host}{base_path}" for scheme in schemes]
        return servers

    def get_global_security(self) -> List[Dict[str, List[str]]]:
        """Returns global security requirements."""
        return self.resolved_dict.get("security", [])

    def get_security_schemes(self) -> Dict[str, Any]:
        """Returns security definitions/schemes configured."""
        if "components" in self.resolved_dict and "securitySchemes" in self.resolved_dict["components"]:
            return self.resolved_dict["components"]["securitySchemes"]
        elif "securityDefinitions" in self.resolved_dict:
            return self.resolved_dict["securityDefinitions"]
        return {}

    def extract_endpoints(self) -> List[Dict[str, Any]]:
        """
        Extracts detailed endpoint data including methods, parameters, request body schemas,
        responses, security constraints, and custom extensions.
        """
        endpoints = []
        paths = self.resolved_dict.get("paths", {})
        global_security = self.get_global_security()
        
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            
            # Paths can have parameters common to all methods
            path_params = path_item.get("parameters", [])
            
            for method, operation in path_item.items():
                if method.lower() not in ["get", "post", "put", "delete", "options", "head", "patch", "trace"]:
                    continue
                
                # Combine path-level and operation-level parameters
                op_params = operation.get("parameters", [])
                all_params = self._merge_parameters(path_params, op_params)
                
                # Extract security overrides or use global security
                security = operation.get("security", global_security)
                
                # Extract Request Body schemas (OpenAPI 3.x vs Swagger 2.0)
                request_body = self._extract_request_body(operation)
                
                # Extract Responses
                responses = self._extract_responses(operation)
                
                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "summary": operation.get("summary", ""),
                    "description": operation.get("description", ""),
                    "operationId": operation.get("operationId", ""),
                    "parameters": all_params,
                    "security": security,
                    "request_body": request_body,
                    "responses": responses,
                    "extensions": {k: v for k, v in operation.items() if k.startswith("x-")}
                })
                
        return endpoints

    def _merge_parameters(self, path_params: List[Dict[str, Any]], op_params: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Merges parameters, overriding path-level parameters with operation-level ones if named identically."""
        merged = {f"{p.get('name')}:{p.get('in')}": p for p in path_params if p.get('name') and p.get('in')}
        for p in op_params:
            if p.get('name') and p.get('in'):
                merged[f"{p.get('name')}:{p.get('in')}"] = p
        return list(merged.values())

    def _extract_request_body(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts Request Body schema info for 3.x or body param for 2.0."""
        # OpenAPI 3.x
        if "requestBody" in operation:
            req_body = operation["requestBody"]
            content = req_body.get("content", {})
            for media_type, media_obj in content.items():
                return {
                    "required": req_body.get("required", False),
                    "media_type": media_type,
                    "schema": media_obj.get("schema", {})
                }
        
        # Swagger 2.0 (Parameters with "in": "body")
        for param in operation.get("parameters", []):
            if param.get("in") == "body":
                return {
                    "required": param.get("required", False),
                    "media_type": "application/json", # Default for body params
                    "schema": param.get("schema", {})
                }
                
        return {}

    def _extract_responses(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts response schemas and headers grouped by status code."""
        extracted = {}
        responses = operation.get("responses", {})
        for status_code, resp in responses.items():
            if not isinstance(resp, dict):
                continue
            
            # OpenAPI 3.x vs Swagger 2.0 schema location
            schema = {}
            media_type = None
            
            if "content" in resp: # OpenAPI 3.x
                for m_type, m_obj in resp["content"].items():
                    media_type = m_type
                    schema = m_obj.get("schema", {})
                    break
            elif "schema" in resp: # Swagger 2.0
                schema = resp["schema"]
                media_type = "application/json"
                
            extracted[status_code] = {
                "description": resp.get("description", ""),
                "headers": resp.get("headers", {}),
                "media_type": media_type,
                "schema": schema
            }
        return extracted
