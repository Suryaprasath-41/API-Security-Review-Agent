import re
from typing import Dict, Any, List

class RuleEngineAgent:
    """
    Executes security rule checks against parsed OpenAPI endpoint data.
    Implements 20 distinct API security checks with detection logic and mitigation.
    """
    def __init__(self):
        # Sensitive names pattern
        self.sensitive_pattern = re.compile(
            r"(pass(word)?|token|secret|key|apikey|credential|ssn|creditcard|ccard|auth|cvv|pin|uuid)", 
            re.IGNORECASE
        )
        # sequential ID path variables (IDOR risk)
        self.sequential_id_pattern = re.compile(r"\{(id|.*id|num|key|code)\}$", re.IGNORECASE)

    def run_checks(self, endpoints: List[Dict[str, Any]], security_schemes: Dict[str, Any], servers: List[str]) -> List[Dict[str, Any]]:
        findings = []
        
        # Rule 7: Weak Protocol check on server configuration
        self._check_weak_protocol(servers, findings)
        
        # Rule 8: Insecure Authentication Scheme
        self._check_weak_auth_definitions(security_schemes, findings)

        for ep in endpoints:
            path = ep["path"]
            method = ep["method"]
            params = ep.get("parameters", [])
            security = ep.get("security", [])
            req_body = ep.get("request_body", {})
            responses = ep.get("responses", {})
            extensions = ep.get("extensions", {})
            
            # Check authentication state
            is_authenticated = self._is_auth_configured(security)

            # Rule 1: Missing Authentication
            if not is_authenticated:
                findings.append({
                    "rule_id": "RULE_MISSING_AUTH",
                    "rule_name": "Missing Authentication Scheme",
                    "path": path,
                    "method": method,
                    "severity": "HIGH",
                    "description": f"Endpoint '{method} {path}' does not enforce any authentication mechanism.",
                    "mitigation": "Protect the endpoint using standard HTTP Authorization headers (Bearer Token, OAuth2) by defining security requirements in the OpenAPI spec.",
                    "exploitability": 5.0,
                    "exposure": 4.5,
                    "business_impact": 4.0
                })

            # Rule 2: Unrestricted DELETE operations
            if method == "DELETE" and not is_authenticated:
                findings.append({
                    "rule_id": "RULE_UNRESTRICTED_DELETE",
                    "rule_name": "Unrestricted destructive HTTP method",
                    "path": path,
                    "method": method,
                    "severity": "CRITICAL",
                    "description": f"Endpoint '{method} {path}' allows destructive file or data deletion operations without credentials.",
                    "mitigation": "Enforce strict Authentication and Role-Based Access Control (RBAC) specifically restricting DELETE requests to administrative accounts.",
                    "exploitability": 5.0,
                    "exposure": 5.0,
                    "business_impact": 5.0
                })

            # Rule 3: Unrestricted PUT/POST/PATCH operations
            if method in ["PUT", "POST", "PATCH"] and not is_authenticated:
                findings.append({
                    "rule_id": "RULE_UNRESTRICTED_WRITE",
                    "rule_name": "Unrestricted state-modifying action",
                    "path": path,
                    "method": method,
                    "severity": "HIGH",
                    "description": f"Endpoint '{method} {path}' allows state changes or resource creation without verification.",
                    "mitigation": "Protect write operations using secure session cookies, JWT/OAuth2 headers, and enforce write-level authorization permissions.",
                    "exploitability": 4.5,
                    "exposure": 4.0,
                    "business_impact": 4.5
                })

            # Rule 4: Sensitive query parameters
            for p in params:
                if p.get("in") == "query" and self.sensitive_pattern.search(p.get("name", "")):
                    findings.append({
                        "rule_id": "RULE_SENSITIVE_QUERY_PARAMS",
                        "rule_name": "Sensitive Data in Query Parameters",
                        "path": path,
                        "method": method,
                        "severity": "HIGH",
                        "description": f"Query parameter '{p.get('name')}' in '{method} {path}' appears to carry authentication keys, secrets, or tokens. Query params are logged in web server logs, browser history, and proxy servers.",
                        "mitigation": "Transmit sensitive credentials or tokens in the HTTP Authorization headers or body payloads rather than URL parameters.",
                        "exploitability": 4.0,
                        "exposure": 4.5,
                        "business_impact": 4.5
                    })

            # Rule 5: Missing Rate Limiting
            rate_limited = False
            for header in ["x-rate-limit", "rate-limit", "x-ratelimit-limit"]:
                if header in extensions or any(header in str(r).lower() for r in responses.values()):
                    rate_limited = True
            if not rate_limited:
                findings.append({
                    "rule_id": "RULE_MISSING_RATE_LIMITING",
                    "rule_name": "Missing Rate Limiting Mechanism",
                    "path": path,
                    "method": method,
                    "severity": "MEDIUM",
                    "description": f"No rate limiting parameters (like 'x-rate-limit' headers) found for '{method} {path}'. Vulnerable to DoS (Denial of Service) or brute-force attacks.",
                    "mitigation": "Implement global rate limits at the API Gateway or application level. Expose rate-limit metadata via standard response headers (Retry-After, X-RateLimit-Limit).",
                    "exploitability": 4.5,
                    "exposure": 3.0,
                    "business_impact": 3.5
                })

            # Rule 6: Sensitive Data Exposure in response schemas
            for status, resp in responses.items():
                schema_str = str(resp.get("schema", {}))
                matched_fields = self.sensitive_pattern.findall(schema_str)
                if matched_fields:
                    sensitive_fields = list(set([m[0] for m in matched_fields if m[0]]))
                    # Filter out innocent values
                    sensitive_fields = [f for f in sensitive_fields if f.lower() not in ["auth", "uuid"]]
                    if sensitive_fields:
                        findings.append({
                            "rule_id": "RULE_EXCESSIVE_DATA_EXPOSURE",
                            "rule_name": "Potential Sensitive Data Exposure in Response Schema",
                            "path": path,
                            "method": method,
                            "severity": "CRITICAL",
                            "description": f"Response schema for status {status} on '{method} {path}' exposes potential secrets or sensitive fields: {', '.join(sensitive_fields)}.",
                            "mitigation": "Audit response schemas. Explicitly redact sensitive properties (passwords, inner keys) in outgoing JSON Serializers or use specific DTOs (Data Transfer Objects).",
                            "exploitability": 3.0,
                            "exposure": 4.5,
                            "business_impact": 5.0
                        })

            # Rule 9: Missing response content-types
            for status, resp in responses.items():
                if not resp.get("media_type"):
                    findings.append({
                        "rule_id": "RULE_MISSING_RESP_CONTENT_TYPE",
                        "rule_name": "Missing Response Content-Type Specification",
                        "path": path,
                        "method": method,
                        "severity": "LOW",
                        "description": f"The response for status code '{status}' on '{method} {path}' does not define a content-type. Browsers might sniff mime-types, risking HTML execution.",
                        "mitigation": "Explicitly define 'content' schemas for each HTTP response status code in the OpenAPI file (e.g. application/json).",
                        "exploitability": 2.0,
                        "exposure": 1.5,
                        "business_impact": 2.0
                    })

            # Rule 10: Wildcard CORS configuration
            cors_exposed = False
            for status, resp in responses.items():
                headers = resp.get("headers", {})
                if "Access-Control-Allow-Origin" in headers:
                    val = headers["Access-Control-Allow-Origin"].get("schema", {}).get("default", "")
                    if val == "*":
                        cors_exposed = True
            if cors_exposed:
                findings.append({
                    "rule_id": "RULE_WILDCARD_CORS",
                    "rule_name": "Wildcard CORS Access Allowed",
                    "path": path,
                    "method": method,
                    "severity": "MEDIUM",
                    "description": f"Endpoint '{method} {path}' returns wildcard cross-origin access configuration ('*'), allowing any website to read data.",
                    "mitigation": "Configure Access-Control-Allow-Origin to dynamically reflect trusted origins and enforce credentials checking rather than allowing raw wildcards.",
                    "exploitability": 3.5,
                    "exposure": 3.5,
                    "business_impact": 3.0
                })

            # Rule 11: SQL Injection risk
            # Rule 16: No Input Validation
            for p in params:
                p_type = p.get("schema", {}).get("type", p.get("type", ""))
                p_name = p.get("name", "")
                if p_type == "string" and p.get("in") in ["query", "path"]:
                    schema = p.get("schema", p)
                    pattern = schema.get("pattern")
                    min_len = schema.get("minLength")
                    max_len = schema.get("maxLength")
                    
                    if not pattern and not min_len and not max_len:
                        findings.append({
                            "rule_id": "RULE_SQL_INJECTION_RISK",
                            "rule_name": "Unvalidated String Parameter SQL Injection Risk",
                            "path": path,
                            "method": method,
                            "severity": "MEDIUM",
                            "description": f"String parameter '{p_name}' in '{method} {path}' lacks any structural validation constraint (pattern, minLength, maxLength), rendering it vulnerable to SQLi or Buffer Overflows.",
                            "mitigation": "Apply specific validation constraints in the OpenAPI spec. Define regex match patterns (pattern) and bounds checking (minLength, maxLength) for all text fields.",
                            "exploitability": 4.0,
                            "exposure": 3.0,
                            "business_impact": 4.0
                        })
                        
                        findings.append({
                            "rule_id": "RULE_NO_INPUT_VALIDATION",
                            "rule_name": "Lack of Input Validation Rules",
                            "path": path,
                            "method": method,
                            "severity": "MEDIUM",
                            "description": f"No input validation schema checks defined for path/query parameter '{p_name}' on '{method} {path}'.",
                            "mitigation": "Implement server-side parameters validation and define standard constraints in the OpenAPI specification.",
                            "exploitability": 4.0,
                            "exposure": 2.5,
                            "business_impact": 3.5
                        })

            # Rule 12: Dangerous File Upload
            is_upload = False
            if req_body:
                media_type = req_body.get("media_type", "")
                if "multipart/form-data" in media_type:
                    is_upload = True
            
            # Legacy check
            for p in params:
                if p.get("in") == "formData" and (p.get("type") == "file" or p.get("schema", {}).get("type") == "file"):
                    is_upload = True
                    
            if is_upload:
                max_size_configured = "x-max-file-size" in extensions or "x-max-file-size" in str(req_body)
                if not max_size_configured:
                    findings.append({
                        "rule_id": "RULE_DANGEROUS_FILE_UPLOAD",
                        "rule_name": "Unrestricted File Upload Endpoint",
                        "path": path,
                        "method": method,
                        "severity": "HIGH",
                        "description": f"Endpoint '{method} {path}' accepts binary files or multipart uploads but fails to state size limits ('x-max-file-size') or file extension whitelists.",
                        "mitigation": "Implement backend verification of file extensions, limit the file payload size at the server and proxy levels, and upload files to non-executable server spaces.",
                        "exploitability": 4.5,
                        "exposure": 4.0,
                        "business_impact": 4.5
                    })

            # Rule 13: Missing request body schema limits
            if req_body and not req_body.get("schema", {}).get("maxProperties") and not req_body.get("schema", {}).get("maxLength"):
                findings.append({
                    "rule_id": "RULE_MISSING_BODY_LIMIT",
                    "rule_name": "Missing Request Payload Constraints",
                    "path": path,
                    "method": method,
                    "severity": "LOW",
                    "description": f"Endpoint '{method} {path}' accepts structured payload but doesn't limit size parameters (maxProperties or maxLength), exposing it to JSON parser Dos.",
                    "mitigation": "Add structural constraint definitions (maxProperties, maxItems) within request schemas to reject excessively nested payloads early.",
                    "exploitability": 3.0,
                    "exposure": 2.0,
                    "business_impact": 2.0
                })

            # Rule 14: Method overriding checked
            # Check for header 'X-HTTP-Method-Override' in parameters
            override_allowed = False
            for p in params:
                if p.get("in") == "header" and p.get("name", "").lower() == "x-http-method-override":
                    override_allowed = True
            if override_allowed:
                findings.append({
                    "rule_id": "RULE_METHOD_OVERRIDE_ENABLED",
                    "rule_name": "HTTP Method Override Allowed",
                    "path": path,
                    "method": method,
                    "severity": "MEDIUM",
                    "description": f"Endpoint '{method} {path}' explicitly supports custom method overriding headers ('X-HTTP-Method-Override'), which bypasses firewalls/WAF rules.",
                    "mitigation": "Disable method overriding headers at the API Gateway or framework level, or ensure that overriding is not parsed automatically by default.",
                    "exploitability": 3.5,
                    "exposure": 2.5,
                    "business_impact": 3.0
                })

            # Rule 15: Weak token usage (API Key in query parameter)
            api_key_query = False
            for scheme_name, scheme_data in security_schemes.items():
                if scheme_data.get("type") == "apiKey" and scheme_data.get("in") == "query":
                    # Check if endpoint uses this scheme
                    for req in security:
                        if scheme_name in req:
                            api_key_query = True
            if api_key_query:
                findings.append({
                    "rule_id": "RULE_WEAK_TOKEN_USAGE",
                    "rule_name": "Weak API Key Placement in URL",
                    "path": path,
                    "method": method,
                    "severity": "MEDIUM",
                    "description": f"Endpoint '{method} {path}' uses API keys embedded in query parameters for authentication.",
                    "mitigation": "Migrate the API key validation process to read from HTTP Authorization headers (e.g., Bearer API_KEY) to avoid logs exposure.",
                    "exploitability": 3.0,
                    "exposure": 4.0,
                    "business_impact": 3.5
                })

            # Rule 17: Missing enum constraints for role-based status params
            for p in params:
                p_name = p.get("name", "").lower()
                p_type = p.get("schema", {}).get("type", p.get("type", ""))
                if p_name in ["status", "state", "role", "type"] and p_type == "string":
                    schema = p.get("schema", p)
                    if "enum" not in schema:
                        findings.append({
                            "rule_id": "RULE_MISSING_ENUM_CONSTRAINTS",
                            "rule_name": "Missing State/Enum Restrictions",
                            "path": path,
                            "method": method,
                            "severity": "LOW",
                            "description": f"Parameter '{p.get('name')}' in '{method} {path}' controls state/role but does not restrict inputs via enum bounds.",
                            "mitigation": "Define explicit enum arrays in the parameter schema defining only valid options (e.g. ['active', 'inactive']).",
                            "exploitability": 2.5,
                            "exposure": 2.0,
                            "business_impact": 2.0
                        })

            # Rule 18: Information exposure in HTTP response headers
            info_header_exposed = False
            for status, resp in responses.items():
                headers = resp.get("headers", {})
                for h_name in ["Server", "X-Powered-By", "X-AspNet-Version"]:
                    if h_name in headers:
                        info_header_exposed = True
            if info_header_exposed:
                findings.append({
                    "rule_id": "RULE_INFO_EXPOSURE_HEADERS",
                    "rule_name": "Vulnerable Software Signature Exposed in Headers",
                    "path": path,
                    "method": method,
                    "severity": "LOW",
                    "description": f"Endpoint response for '{method} {path}' returns server headers exposing server brand, framework, or versions.",
                    "mitigation": "Configure the web server or reverse proxy (NGINX, Apache) to strip 'Server' and 'X-Powered-By' headers prior to forwarding.",
                    "exploitability": 1.5,
                    "exposure": 2.0,
                    "business_impact": 1.5
                })

            # Rule 19: Publicly accessible Admin panel endpoints
            is_admin_path = "/admin" in path.lower() or "/actuator" in path.lower() or "/management" in path.lower()
            if is_admin_path and not is_authenticated:
                findings.append({
                    "rule_id": "RULE_PUBLIC_ADMIN_PANEL",
                    "rule_name": "Public Administrative Endpoints Exposed",
                    "path": path,
                    "method": method,
                    "severity": "CRITICAL",
                    "description": f"Administrative panel pathway '{path}' detected without enforced authentication controls.",
                    "mitigation": "Restrict admin pathways strictly. Ensure authorization controls validation at network levels (WAF, VPN gateways) and enforce robust Multi-Factor Authentication.",
                    "exploitability": 5.0,
                    "exposure": 4.5,
                    "business_impact": 5.0
                })

            # Rule 20: Insecure IDOR risk
            # Look for paths like /users/{id}
            if self.sequential_id_pattern.search(path):
                findings.append({
                    "rule_id": "RULE_INSECURE_IDOR_RISK",
                    "rule_name": "Potential Insecure Direct Object Reference (IDOR)",
                    "path": path,
                    "method": method,
                    "severity": "HIGH",
                    "description": f"Resource endpoint '{method} {path}' uses sequential integer identifiers as resource paths without explicit authorization limits context check.",
                    "mitigation": "Replace sequential integers with cryptographically secure random values (UUIDv4) and validate user permissions relative to the resource owner on every request.",
                    "exploitability": 4.0,
                    "exposure": 4.5,
                    "business_impact": 4.5
                })

        return findings

    def _is_auth_configured(self, security: List[Dict[str, List[str]]]) -> bool:
        """Determines if there is a security definition applied. Returns False if explicitly empty list []."""
        if not security:
            return False
        # If security is present, verify it isn't an empty dictionary [{}] which means auth is optional
        for req in security:
            if isinstance(req, dict) and len(req) > 0:
                return True
        return False

    def _check_weak_protocol(self, servers: List[str], findings: List[Dict[str, Any]]):
        """Rule 7: Insecure HTTP Protocol configuration in servers list."""
        for s in servers:
            if s.startswith("http://"):
                findings.append({
                    "rule_id": "RULE_WEAK_PROTOCOL",
                    "rule_name": "Insecure Server Communication Protocol (HTTP)",
                    "path": "GLOBAL_CONFIG",
                    "method": "SERVER",
                    "severity": "HIGH",
                    "description": f"API server configured to communicate over plaintext protocol: '{s}'. Traffic will be exposed in transit.",
                    "mitigation": "Update the host references to enforce secure TLS encrypted transport (HTTPS). Require HSTS headers.",
                    "exploitability": 4.0,
                    "exposure": 4.0,
                    "business_impact": 4.5
                })
                break

    def _check_weak_auth_definitions(self, security_schemes: Dict[str, Any], findings: List[Dict[str, Any]]):
        """Rule 8: Insecure Basic Auth configuration."""
        for name, scheme in security_schemes.items():
            if scheme.get("type") == "http" and scheme.get("scheme") == "basic":
                findings.append({
                    "rule_id": "RULE_BASIC_AUTH_INSECURE",
                    "rule_name": "Insecure HTTP Basic Authentication Configured",
                    "path": "GLOBAL_CONFIG",
                    "method": "SECURITY",
                    "severity": "HIGH",
                    "description": f"Basic authentication scheme '{name}' exposes credentials through simple base64 strings in the Header.",
                    "mitigation": "Upgrade authentication protocols to standard tokens like JWT Bearer schemes or integrate secure OpenID Connect/OAuth2 flows.",
                    "exploitability": 3.5,
                    "exposure": 4.0,
                    "business_impact": 4.0
                })
