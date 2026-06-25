from typing import Dict, Any

class OwaspAgent:
    """
    Maps rule findings to OWASP API Security Top 10 (2023) categories
    and adds relevant descriptions and prevention advice.
    """
    
    OWASP_2023_METADATA = {
        "API1:2023": {
            "title": "Broken Object Level Authorization (BOLA)",
            "description": "APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface Level Access Control issue. User input must be checked to ensure they have rights to the requested object.",
            "prevention": "Implement authorization checks based on user identity/roles relative to the requested object ID. Use random non-guessable identifiers (UUIDv4) instead of database IDs."
        },
        "API2:2023": {
            "title": "Broken Authentication",
            "description": "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or exploit implementation flaws to assume identities.",
            "prevention": "Adopt standard token authentication (OAuth2 / OpenID Connect / JWT). Do not pass keys/secrets in query parameters. Set secure expiration policies for tokens."
        },
        "API3:2023": {
            "title": "Broken Object Property Level Authorization",
            "description": "This category combines Exposure of Sensitive Data and Mass Assignment. Attackers can read or modify sensitive object property values that they should not have access to.",
            "prevention": "Use specific Data Transfer Objects (DTOs) for requests and responses. Filter out internal properties (like user roles, password hashes) in serialize methods."
        },
        "API4:2023": {
            "title": "Unrestricted Resource Consumption",
            "description": "Lack of resource limiting leads to denial of service, resource exhaustion, or excessive cloud hosting expenditures.",
            "prevention": "Implement rate limiting (requests/IP/minute). Limit payload sizes, array lengths, memory allocation, and verify third-party API timeout configurations."
        },
        "API5:2023": {
            "title": "Broken Function Level Authorization",
            "description": "Complex access control policies with hierarchies can be bypassed by sending appropriate HTTP methods or paths, giving unauthorized functions to users.",
            "prevention": "Configure explicit, role-based security configurations at both the path and HTTP method levels. Require admin-level token claims for administrative endpoints."
        },
        "API6:2023": {
            "title": "Unrestricted Access to Sensitive Business Flows",
            "description": "Exposing business logic flows (like purchase checkout, user registrations) without capping frequency allows automated bots to abuse policies.",
            "prevention": "Enforce captchas, multi-factor validations, bot-detection tools, and specialized rate limits on business-critical entry points."
        },
        "API7:2023": {
            "title": "Server-Side Request Forgery (SSRF)",
            "description": "SSRF occurs when an API fetches a remote resource without validating the user-supplied URL, allowing attackers to query internal network locations.",
            "prevention": "Sanitize and whitelist remote request destinations. Avoid allowing raw URL parameters to be directly requested by the server backend."
        },
        "API8:2023": {
            "title": "Security Misconfiguration",
            "description": "APIs often expose verbose errors, stack traces, insecure protocols, debug tools, or wildcards that help attackers gather network intelligence.",
            "prevention": "Disable directory listing, strip debugging headers, enforce strict CORS origins, disable plaintext HTTP transport, and configure clean error mappings."
        },
        "API9:2023": {
            "title": "Improper Assets Management",
            "description": "APIs tend to expose more endpoints than traditional web applications, making updated documentation, version deprecation, and hosting hygiene critical.",
            "prevention": "Document all API versions. Deprecate and remove stale, old, or beta testing endpoints from the production environment."
        },
        "API10:2023": {
            "title": "Unsafe Consumption of APIs / Injection",
            "description": "APIs trust data received from third-party APIs or client requests without sanitization, leading to SQL Injection, command execution, or parser overflows.",
            "prevention": "Never trust client input. Implement strict parameter schema validation (regex patterns, bounds) and use parameterized queries/ORM models."
        }
    }

    # Rule to OWASP key mapping
    RULE_MAP = {
        "RULE_MISSING_AUTH": "API2:2023",
        "RULE_UNRESTRICTED_DELETE": "API5:2023",
        "RULE_UNRESTRICTED_WRITE": "API5:2023",
        "RULE_SENSITIVE_QUERY_PARAMS": "API3:2023",
        "RULE_MISSING_RATE_LIMITING": "API4:2023",
        "RULE_EXCESSIVE_DATA_EXPOSURE": "API3:2023",
        "RULE_WEAK_PROTOCOL": "API8:2023",
        "RULE_BASIC_AUTH_INSECURE": "API2:2023",
        "RULE_MISSING_RESP_CONTENT_TYPE": "API8:2023",
        "RULE_WILDCARD_CORS": "API8:2023",
        "RULE_SQL_INJECTION_RISK": "API10:2023",
        "RULE_DANGEROUS_FILE_UPLOAD": "API4:2023",
        "RULE_MISSING_BODY_LIMIT": "API4:2023",
        "RULE_METHOD_OVERRIDE_ENABLED": "API8:2023",
        "RULE_WEAK_TOKEN_USAGE": "API2:2023",
        "RULE_NO_INPUT_VALIDATION": "API10:2023",
        "RULE_MISSING_ENUM_CONSTRAINTS": "API8:2023",
        "RULE_INFO_EXPOSURE_HEADERS": "API8:2023",
        "RULE_PUBLIC_ADMIN_PANEL": "API5:2023",
        "RULE_INSECURE_IDOR_RISK": "API1:2023"
    }

    def map_findings(self, findings: list) -> list:
        mapped_findings = []
        for f in findings:
            rule_id = f.get("rule_id")
            owasp_cat = self.RULE_MAP.get(rule_id, "API8:2023") # Default to Security Misconfiguration if unknown
            meta = self.OWASP_2023_METADATA.get(owasp_cat, {})
            
            # Copy finding and merge OWASP data
            f_mapped = f.copy()
            f_mapped["owasp_category"] = owasp_cat
            f_mapped["owasp_title"] = meta.get("title", "Unknown OWASP Risk")
            
            # Append general prevention guidelines to the specific rule recommendation
            f_mapped["mitigation"] = f_mapped.get("mitigation", "") + "\n\n**OWASP Prevention Strategy:** " + meta.get("prevention", "")
            
            mapped_findings.append(f_mapped)
            
        return mapped_findings
