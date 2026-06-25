import os
import requests
import json
import logging
from typing import Dict, Any, List
from app.config import OPENAI_API_KEY, OLLAMA_HOST

logger = logging.getLogger(__name__)

class LLMAgent:
    """
    Explains API vulnerabilities, outlines exploit paths, and suggests code-level remediations.
    Connects to OpenAI or Ollama, falling back to a detailed rule knowledge base if offline.
    """
    
    # Static Knowledge Base for offline fallbacks
    KNOWLEDGE_BASE = {
        "RULE_MISSING_AUTH": {
            "explanation": "Because this endpoint lacks authentication, any user on the internet can send requests to it. Attackers can call this API programmatically, leading to resource abuse, database pollution, or leakage of unauthenticated actions.",
            "mitigation_snippet": "In FastAPI, protect the route using a Security dependency:\n\n```python\nfrom fastapi import Depends, Security\nfrom fastapi.security import HTTPBearer, HTTPAuthorizationCredentials\n\nsecurity_scheme = HTTPBearer()\n\n@app.get('/users')\ndef read_users(credentials: HTTPAuthorizationCredentials = Security(security_scheme)):\n    token = credentials.credentials\n    # Validate JWT here\n    return {'status': 'authenticated'}\n```"
        },
        "RULE_UNRESTRICTED_DELETE": {
            "explanation": "This administrative deletion endpoint has zero access controls. An unauthorized attacker can issue standard HTTP DELETE requests to wipe database tables, destroy application state, or delete sensitive records without trace.",
            "mitigation_snippet": "Implement strict Role-Based Access Control (RBAC) validations:\n\n```python\n@app.delete('/admin/deleteUser', dependencies=[Depends(require_admin_role)])\ndef delete_user(user_id: int):\n    db.delete_user(user_id)\n    return {'status': 'deleted'}\n```"
        },
        "RULE_UNRESTRICTED_WRITE": {
            "explanation": "State-modifying operations (PUT/POST/PATCH) are exposed publicly. Anyone can inject new profiles, edit record configurations, overwrite application settings, or perform unauthorized transactions.",
            "mitigation_snippet": "Enforce authentication and input schema checks on modify routes:\n\n```python\n@app.put('/items/{item_id}')\ndef update_item(item_id: str, item: ItemSchema, user = Depends(get_current_user)):\n    db.save(item)\n    return {'status': 'updated'}\n```"
        },
        "RULE_SENSITIVE_QUERY_PARAMS": {
            "explanation": "URLs are logged in plain text by intermediate reverse proxies, browser history, router logs, and load balancers. Exposing secrets/keys/tokens in the query string allows attackers with access to log systems to compromise credentials easily.",
            "mitigation_snippet": "Read token credentials from the standard HTTP Authorization header:\n\n```python\n# Request Header:\n# Authorization: Bearer <your_api_token>\n\n# Backend retrieval:\n@app.get('/data')\ndef get_data(authorization: str = Header(None)):\n    if not authorization or not authorization.startswith('Bearer '):\n        raise HTTPException(status_code=401, detail='Missing Bearer token')\n    token = authorization.split(' ')[1]\n```"
        },
        "RULE_MISSING_RATE_LIMITING": {
            "explanation": "Without rate limits, attackers can launch distributed denial of service (DDoS) requests, perform credential stuffing attacks, or harvest endpoints recursively, which drains computing resources and increases cloud costs.",
            "mitigation_snippet": "Integrate rate-limiting middleware (like slowapi in FastAPI):\n\n```python\nfrom slowapi import Limiter\nfrom slowapi.util import get_remote_address\n\nlimiter = Limiter(key_func=get_remote_address)\n\n@app.get('/login')\n@limiter.limit('5/minute')\ndef login(request: Request):\n    return {'status': 'attempted'}\n```"
        },
        "RULE_EXCESSIVE_DATA_EXPOSURE": {
            "explanation": "The API response schema contains property definitions that expose critical secrets (like passwords, keys, or SSNs). Even if the client-side UI hides these values, the raw JSON payload contains them, giving attackers access to credentials.",
            "mitigation_snippet": "Implement response filters or specific Data Transfer Objects (DTOs) with Pydantic:\n\n```python\nfrom pydantic import BaseModel, EmailStr\n\nclass UserResponse(BaseModel):\n    id: int\n    username: str\n    email: EmailStr\n    # Exclude password_hash or ssn fields here\n\n@app.get('/users/{id}', response_model=UserResponse)\ndef get_user(id: int):\n    return db.query_user(id)\n```"
        },
        "RULE_WEAK_PROTOCOL": {
            "explanation": "Plaintext HTTP communications send information across the network without encryption. Attackers on public Wi-Fi or local networks can run simple packet sniffing (Man-in-the-Middle) to steal API payloads, cookies, and tokens.",
            "mitigation_snippet": "Force SSL redirection and update configuration server targets:\n\n```yaml\n# OpenAPI Server definition:\nservers:\n  - url: https://api.production.com/v1\n    description: Secure Production API (HTTPS)\n```"
        },
        "RULE_BASIC_AUTH_INSECURE": {
            "explanation": "Basic authentication transmits usernames and passwords as Base64 strings, which can be easily decoded. If intercepted or stored, attackers gain complete password keys.",
            "mitigation_snippet": "Upgrade from Basic Auth to Token Authentication (e.g. JWT):\n\n```python\n# Generate a secure JWT instead of prompting for basic passwords every request\n# Send JWT in: Authorization: Bearer <token>\n```"
        },
        "RULE_MISSING_RESP_CONTENT_TYPE": {
            "explanation": "If an HTTP response does not contain an explicit content-type, client browsers might perform 'MIME-sniffing' and interpret JSON responses as execute-ready HTML scripts, triggering Cross-Site Scripting (XSS).",
            "mitigation_snippet": "Explicitly set JSON content-type header on responses:\n\n```python\nfrom fastapi.responses import JSONResponse\n\n@app.get('/data')\ndef get_data():\n    return JSONResponse(\n        content={'data': 'value'},\n        headers={'Content-Type': 'application/json'}\n    )\n```"
        },
        "RULE_WILDCARD_CORS": {
            "explanation": "Allowing '*' as an Access-Control-Allow-Origin header enables any external website to issue requests and read API response payloads, compromising user privacy and session data.",
            "mitigation_snippet": "Restrict origin access lists in CORS configuration middleware:\n\n```python\nfrom fastapi.middleware.cors import CORSMiddleware\n\napp.add_middleware(\n    CORSMiddleware,\n    allow_origins=['https://trustedapp.com'],\n    allow_credentials=True,\n    allow_methods=['GET', 'POST'],\n    allow_headers=['*'],\n)\n```"
        },
        "RULE_SQL_INJECTION_RISK": {
            "explanation": "Unvalidated parameters fed directly into SQL statements can break syntax boundaries, allowing attackers to write arbitrary SQL commands to extract complete databases, bypass checks, or wipe files.",
            "mitigation_snippet": "Utilize parameterized queries, Object Relational Mappers (ORM), and strict input regex checks:\n\n```python\n# Secure ORM query:\nuser = db.query(User).filter(User.username == username).first()\n\n# Or parameterized raw queries:\ncursor.execute('SELECT * FROM users WHERE username = ?', (username,))\n```"
        },
        "RULE_DANGEROUS_FILE_UPLOAD": {
            "explanation": "Uncontrolled file uploads allow attackers to host malicious scripts, web shells, or malware. An attacker can upload an executable file (e.g. `.php` or `.py`) and call it to take control of the server.",
            "mitigation_snippet": "Enforce whitelisted file extensions and limit max file size limits:\n\n```python\nALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}\nMAX_FILE_SIZE = 5 * 1024 * 1024 # 5MB\n\ndef validate_file(filename: str, size: int):\n    ext = filename.rsplit('.', 1)[-1].lower()\n    if ext not in ALLOWED_EXTENSIONS:\n        raise HTTPException(status_code=400, detail='Invalid file type')\n    if size > MAX_FILE_SIZE:\n        raise HTTPException(status_code=400, detail='File too large')\n```"
        },
        "RULE_MISSING_BODY_LIMIT": {
            "explanation": "Allowing clients to upload massive JSON payloads can exhaust server memory, lock up parser event-loops, or lead to Denial of Service (DoS).",
            "mitigation_snippet": "Set global body payload limit rules on the reverse proxy (like client_max_body_size in Nginx) or server middleware."
        },
        "RULE_METHOD_OVERRIDE_ENABLED": {
            "explanation": "Supporting headers like X-HTTP-Method-Override allows clients to tunnel DELETE or PUT commands through standard GET/POST queries, bypassing corporate firewall restrictions.",
            "mitigation_snippet": "Disable interpretation of method override headers in API Gateway and server middleware configurations."
        },
        "RULE_WEAK_TOKEN_USAGE": {
            "explanation": "API Keys passed in query parameters are insecure. They are easily intercepted, cached, or saved in browser configurations, bypassing secrecy constraints.",
            "mitigation_snippet": "Require API Keys or Bearer tokens in headers:\n\n```python\n# Header: X-API-KEY: key_value\n@app.get('/secure-api')\ndef secure_route(api_key: str = Header(..., alias='X-API-KEY')):\n    if api_key != EXPECTED_KEY:\n        raise HTTPException(status_code=403, detail='Forbidden')\n```"
        },
        "RULE_NO_INPUT_VALIDATION": {
            "explanation": "Exposing input variables without boundaries allows formatting errors, numeric overflows, and unexpected payload crashes. This bypasses structural validation layers.",
            "mitigation_snippet": "Use Pydantic schema validation patterns:\n\n```python\nfrom pydantic import BaseModel, Field\n\nclass QueryModel(BaseModel):\n    item_id: int = Field(..., ge=1, le=100000)\n    search_query: str = Field(..., min_length=3, max_length=50, pattern='^[a-zA-Z0-9 ]+$')\n```"
        },
        "RULE_MISSING_ENUM_CONSTRAINTS": {
            "explanation": "Exposing variables without enum boundaries allows clients to send invalid configurations (e.g. user roles like 'superuser' or status values like 'corrupted'), causing backend logic issues.",
            "mitigation_snippet": "Expose parameters using Enum definitions in Pydantic/FastAPI:\n\n```python\nfrom enum import Enum\n\nclass UserRole(str, Enum):\n    ADMIN = 'admin'\n    USER = 'user'\n    GUEST = 'guest'\n\n@app.get('/users')\ndef list_users(role: UserRole):\n    return {'selected_role': role}\n```"
        },
        "RULE_INFO_EXPOSURE_HEADERS": {
            "explanation": "Leaking platform names and versions helps attackers quickly identify server CVEs (Known Vulnerabilities) to target operations.",
            "mitigation_snippet": "Strip headers using reverse proxy rules:\n\n```nginx\n# In Nginx configuration:\nserver_tokens off;\nproxy_hide_header X-Powered-By;\n```"
        },
        "RULE_PUBLIC_ADMIN_PANEL": {
            "explanation": "Exposing administrative systems to the open internet allows brute force, credential stuffing, and unauthenticated control over underlying app components.",
            "mitigation_snippet": "Protect Admin routes using RBAC checks and IP-whitelisting:\n\n```python\n@app.get('/admin/dashboard', dependencies=[Depends(verify_ip_whitelist)])\ndef admin_dash(user = Depends(require_admin)):\n    return {'status': 'ok'}\n```"
        },
        "RULE_INSECURE_IDOR_RISK": {
            "explanation": "Exposing resource records through sequential integers (like `/users/1`, `/users/2`) allows attackers to sweep the numbers to download the entire database.",
            "mitigation_snippet": "Switch database primary keys to UUIDs and validate user permissions:\n\n```python\nimport uuid\n\n@app.get('/invoices/{invoice_uuid}')\ndef get_invoice(invoice_uuid: uuid.UUID, user = Depends(get_current_user)):\n    invoice = db.find_invoice(invoice_uuid)\n    if invoice.owner_id != user.id:\n        raise HTTPException(status_code=403, detail='Unauthorized')\n    return invoice\n```"
        }
    }

    def __init__(self):
        self.use_openai = False
        self.use_ollama = False
        
        # Test OpenAI connection once on startup
        if OPENAI_API_KEY:
            try:
                # Let's verify OpenAI is reachable with a short 2-second timeout
                res = requests.get("https://api.openai.com/v1/models", headers={"Authorization": f"Bearer {OPENAI_API_KEY}"}, timeout=2.0)
                if res.status_code == 200:
                    self.use_openai = True
                else:
                    logger.warning(f"OpenAI test connection returned {res.status_code}. Skipping OpenAI.")
            except Exception as e:
                logger.warning(f"OpenAI test connection failed: {e}. Skipping OpenAI.")
                
        # Test Ollama connection once on startup if OpenAI is not active
        if not self.use_openai:
            if self._is_ollama_available():
                self.use_ollama = True

    def explain_finding(self, rule_id: str, method: str, path: str) -> Dict[str, str]:
        """
        Generates explanation and mitigation snippets.
        Utilizes LLMs (OpenAI/Ollama) if reachable, else falls back to local knowledge base.
        """
        # Try LLM first if environment keys/host configured
        llm_response = None
        if self.use_openai:
            llm_response = self._query_openai(rule_id, method, path)
        elif self.use_ollama:
            llm_response = self._query_ollama(rule_id, method, path)
            
        if llm_response:
            return llm_response
            
        # Fallback to local detailed template
        fallback = self.KNOWLEDGE_BASE.get(
            rule_id, 
            {
                "explanation": f"The endpoint '{method} {path}' violated policy '{rule_id}'. Security controls must be implemented to prevent unauthorized usage or exploit vectors.",
                "mitigation_snippet": "Ensure standard secure software engineering principles, parameter checks, and strict token credentials checking are enforced."
            }
        )
        return fallback

    def _query_openai(self, rule_id: str, method: str, path: str) -> Dict[str, str]:
        """Queries OpenAI chat completions API using requests."""
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}"
        }
        
        prompt = self._build_prompt(rule_id, method, path)
        
        payload = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a Senior DevSecOps Architect and API Security Specialist. You explain vulnerabilities clearly and return structured JSON format with two keys: 'explanation' and 'mitigation_snippet'."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=10)
            if response.status_code == 200:
                data = response.json()
                content = json.loads(data["choices"][0]["message"]["content"])
                return {
                    "explanation": content.get("explanation", ""),
                    "mitigation_snippet": content.get("mitigation_snippet", "")
                }
        except Exception as e:
            logger.warning(f"OpenAI API call failed: {e}. Falling back.")
        return None

    def _is_ollama_available(self) -> bool:
        """Helper to quickly check if local Ollama server is alive."""
        try:
            res = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=1.5)
            return res.status_code == 200
        except Exception:
            return False

    def _query_ollama(self, rule_id: str, method: str, path: str) -> Dict[str, str]:
        """Queries local Ollama instance running llama3 or similar model."""
        url = f"{OLLAMA_HOST}/api/generate"
        
        prompt = self._build_prompt(rule_id, method, path)
        system_instruction = "You are an API Security AI. Explain the security vulnerability and mitigation. You must output JSON format with 'explanation' and 'mitigation_snippet' keys. Do not include markdown code block formatting outside the JSON."
        
        payload = {
            "model": "llama3",
            "prompt": f"{system_instruction}\n\nTask:\n{prompt}",
            "stream": False,
            "format": "json"
        }
        
        try:
            response = requests.post(url, json=payload, timeout=15)
            if response.status_code == 200:
                data = response.json()
                content = json.loads(data["response"])
                return {
                    "explanation": content.get("explanation", ""),
                    "mitigation_snippet": content.get("mitigation_snippet", "")
                }
        except Exception as e:
            logger.warning(f"Ollama API call failed: {e}. Falling back.")
        return None

    def _build_prompt(self, rule_id: str, method: str, path: str) -> str:
        """Constructs security analysis prompt."""
        return (
            f"Vulnerability ID: {rule_id}\n"
            f"HTTP Location: {method} {path}\n\n"
            f"Please output a JSON response containing:\n"
            f"1. 'explanation': A 2-3 sentence explanation of why this configuration is vulnerable and what an attacker could do.\n"
            f"2. 'mitigation_snippet': A styled markdown code snippet showing how to fix it in a programming framework (FastAPI, Python, or configuration example)."
        )
