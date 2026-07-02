import streamlit as st
import requests
import os
import sqlite3
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
from datetime import datetime

# Setup paths and fallback imports
from app.config import REPORT_DIR, DATABASE_PATH
from app.database import get_all_scans, get_scan, get_scan_findings, get_scan_reports, init_db, save_specification
from app.agents.graph import run_security_scan

# Backend URL
API_URL = "http://localhost:8000"

# Set page configuration
st.set_page_config(
    page_title="🛡️ Intelligent API Security Review Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber-Security Dark CSS Theme & Styling
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=JetBrains+Mono:wght@400;700&display=swap');
    
    /* Set main fonts and dark theme */
    html, body, [class*="css"], .stApp {
        font-family: 'Outfit', sans-serif;
        background-color: #0b0f19;
        color: #f1f5f9;
    }
    
    /* Sidebar styling */
    section[data-testid="stSidebar"] {
        background-color: #0f172a !important;
        border-right: 1px solid rgba(59, 130, 246, 0.1) !important;
    }
    
    section[data-testid="stSidebar"] * {
        color: #f1f5f9 !important;
    }
    
    /* Header Console Box */
    .main-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
        padding: 2.2rem;
        border-radius: 16px;
        border: 1px solid rgba(59, 130, 246, 0.2);
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        position: relative;
        overflow: hidden;
    }
    
    .main-header::after {
        content: '';
        position: absolute;
        top: -50%;
        left: -50%;
        width: 200%;
        height: 200%;
        background: radial-gradient(circle, rgba(59, 130, 246, 0.08) 0%, transparent 70%);
        pointer-events: none;
    }
    
    .main-header h1 {
        font-family: 'Outfit', sans-serif;
        font-weight: 700;
        font-size: 2.6rem;
        margin: 0;
        background: linear-gradient(90deg, #60a5fa, #38bdf8, #818cf8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        letter-spacing: -0.5px;
    }
    
    .main-header p {
        font-size: 1.1rem;
        font-weight: 300;
        color: #94a3b8;
        margin-top: 0.5rem;
    }
    
    /* Glowing card containers */
    .card {
        background: rgba(30, 41, 59, 0.55);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        padding: 1.5rem;
        border-radius: 12px;
        border: 1px solid rgba(255, 255, 255, 0.05);
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        margin-bottom: 1.5rem;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }
    
    .card:hover {
        transform: translateY(-2px);
        border-color: rgba(59, 130, 246, 0.35);
        box-shadow: 0 8px 30px rgba(59, 130, 246, 0.15);
        background: rgba(30, 41, 59, 0.7);
    }
    
    /* Metric dashboard grid */
    .metric-container {
        display: flex;
        justify-content: space-between;
        gap: 1rem;
        margin-bottom: 2rem;
        flex-wrap: wrap;
    }
    
    .metric-card {
        background: rgba(15, 23, 42, 0.6);
        backdrop-filter: blur(8px);
        padding: 1.2rem;
        border-radius: 12px;
        text-align: center;
        min-width: 140px;
        flex: 1;
        border: 1px solid rgba(255, 255, 255, 0.04);
        border-top: 4px solid #64748B;
        transition: all 0.3s ease;
    }
    
    .metric-card:hover {
        transform: translateY(-4px);
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
        background: rgba(15, 23, 42, 0.8);
    }
    
    .metric-card.critical { border-top-color: #ef4444; }
    .metric-card.high { border-top-color: #f97316; }
    .metric-card.medium { border-top-color: #eab308; }
    .metric-card.low { border-top-color: #3b82f6; }
    
    .metric-val {
        font-size: 2.2rem;
        font-weight: 700;
        margin-top: 0.2rem;
    }
    
    .metric-card.critical .metric-val { color: #ef4444; text-shadow: 0 0 15px rgba(239, 68, 68, 0.25); }
    .metric-card.high .metric-val { color: #f97316; text-shadow: 0 0 15px rgba(249, 115, 22, 0.25); }
    .metric-card.medium .metric-val { color: #eab308; text-shadow: 0 0 15px rgba(234, 179, 8, 0.25); }
    .metric-card.low .metric-val { color: #3b82f6; text-shadow: 0 0 15px rgba(59, 130, 246, 0.25); }
    
    /* Badges */
    .badge {
        padding: 0.3rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.72rem;
        font-weight: 700;
        color: white;
        display: inline-block;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.25);
    }
    .badge.critical { background: linear-gradient(135deg, #991b1b, #ef4444); }
    .badge.high { background: linear-gradient(135deg, #9a3412, #f97316); }
    .badge.medium { background: linear-gradient(135deg, #854d0e, #eab308); color: #0b0f19; }
    .badge.low { background: linear-gradient(135deg, #1e40af, #3b82f6); }
    
    /* Route display standard */
    .route-display {
        font-family: 'JetBrains Mono', Courier, monospace;
        font-weight: 600;
        background: #0f172a;
        padding: 0.3rem 0.7rem;
        border-radius: 6px;
        color: #38bdf8;
        border: 1px solid rgba(56, 189, 248, 0.15);
        font-size: 0.9rem;
    }
    
    /* Exploit sandbox styling */
    .exploit-box {
        background-color: #020617;
        border-left: 4px solid #f43f5e;
        border-radius: 8px;
        padding: 1.2rem;
        margin: 1rem 0;
        font-family: 'JetBrains Mono', monospace;
        color: #cbd5e1;
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    }
    
    .verify-box {
        background-color: #020617;
        border-left: 4px solid #10b981;
        border-radius: 8px;
        padding: 1.2rem;
        margin: 1rem 0;
        font-family: 'JetBrains Mono', monospace;
        color: #cbd5e1;
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    }
    
    /* Segmented select control custom headers */
    .section-title {
        font-size: 1.3rem;
        font-weight: 600;
        border-bottom: 2px solid rgba(59, 130, 246, 0.2);
        padding-bottom: 0.4rem;
        margin-bottom: 1.2rem;
        color: #f1f5f9;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    
    /* custom input elements */
    .stTextInput>div>div>input {
        background-color: #1e293b !important;
        color: #f1f5f9 !important;
        border-color: rgba(255,255,255,0.1) !important;
    }
    </style>
""", unsafe_allow_html=True)

# Static Exploit Simulation Maps
EXPLOIT_SIMULATION = {
    "RULE_MISSING_AUTH": {
        "exploit": "curl -X {method} \"http://api.target.local{path}\" \\\n  -H \"Accept: application/json\"",
        "verify": "curl -i -X {method} \"http://api.target.local{path}\" \\\n  -H \"Accept: application/json\"\n\n# Expected Response:\n# HTTP/1.1 401 Unauthorized"
    },
    "RULE_UNRESTRICTED_DELETE": {
        "exploit": "curl -X DELETE \"http://api.target.local{path}\" \\\n  -H \"Accept: application/json\"",
        "verify": "curl -i -X DELETE \"http://api.target.local{path}\" \\\n  -H \"Accept: application/json\"\n\n# Expected Response:\n# HTTP/1.1 401 Unauthorized or HTTP/1.1 403 Forbidden"
    },
    "RULE_UNRESTRICTED_WRITE": {
        "exploit": "curl -X {method} \"http://api.target.local{path}\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{{\"key\": \"value\"}}'",
        "verify": "curl -i -X {method} \"http://api.target.local{path}\" \\\n  -H \"Content-Type: application/json\"\n\n# Expected Response:\n# HTTP/1.1 401 Unauthorized"
    },
    "RULE_SENSITIVE_QUERY_PARAMS": {
        "exploit": "curl -X {method} \"http://api.target.local{path}?token=secret_val\"",
        "verify": "Verify server/proxy access logs for query string secrets.\nEnforce Bearer headers:\ncurl -X {method} \"http://api.target.local{path}\" \\\n  -H \"Authorization: Bearer secret_val\""
    },
    "RULE_MISSING_RATE_LIMITING": {
        "exploit": "for i in {{1..50}}; do curl -s -o /dev/null -w \"%%{{http_code}}\\n\" -X {method} \"http://api.target.local{path}\"; done",
        "verify": "Send bursts of requests. Ensure the server begins returning:\n# Expected Response:\n# HTTP/1.1 429 Too Many Requests"
    },
    "RULE_EXCESSIVE_DATA_EXPOSURE": {
        "exploit": "curl -X {method} \"http://api.target.local{path}\"",
        "verify": "Check returned JSON properties. Ensure sensitive attributes (like passwords, keys, salts) are removed."
    },
    "RULE_WEAK_PROTOCOL": {
        "exploit": "curl -k -i -X {method} \"http://api.target.local{path}\" (Plaintext unencrypted transport check)",
        "verify": "Ensure the API server triggers HTTP-to-HTTPS redirect. Target must only serve over TLS."
    },
    "RULE_BASIC_AUTH_INSECURE": {
        "exploit": "curl -X {method} \"http://api.target.local{path}\" -u \"username:password\"",
        "verify": "Decommission Basic Auth headers. Implement standard JWT/OAuth2 Bearer token verifications."
    },
    "RULE_MISSING_RESP_CONTENT_TYPE": {
        "exploit": "curl -i -X {method} \"http://api.target.local{path}\"",
        "verify": "Check for Content-Type response headers. Verify it is set to 'application/json' to prevent XSS MIME sniffing."
    },
    "RULE_WILDCARD_CORS": {
        "exploit": "curl -i -X {method} \"http://api.target.local{path}\" -H \"Origin: http://malicious.com\"",
        "verify": "Ensure Access-Control-Allow-Origin is not '*'. Reject random CORS entries. Return specific trusted whitelist hosts."
    },
    "RULE_SQL_INJECTION_RISK": {
        "exploit": "curl -X {method} \"http://api.target.local{path}?query=1'%%20OR%%20'1'='1\"",
        "verify": "Implement parameterized statements / ORM queries. Enforce regex to filter special SQL characters."
    },
    "RULE_DANGEROUS_FILE_UPLOAD": {
        "exploit": "curl -X {method} \"http://api.target.local{path}\" -F \"file=@webshell.php\"",
        "verify": "Test file upload with .php, .exe, or .sh extensions. Ensure the backend returns a strict HTTP 400 rejection."
    },
    "RULE_MISSING_BODY_LIMIT": {
        "exploit": "dd if=/dev/zero bs=1M count=15 | curl -X {method} \"http://api.target.local{path}\" -H \"Content-Type: application/json\" -d @-",
        "verify": "Send a payload exceeding 2MB. Verify response. The Gateway/Server should return:\n# HTTP/1.1 413 Payload Too Large"
    },
    "RULE_METHOD_OVERRIDE_ENABLED": {
        "exploit": "curl -X POST \"http://api.target.local{path}\" -H \"X-HTTP-Method-Override: DELETE\"",
        "verify": "Ensure gateway rejects X-HTTP-Method-Override requests. Enforce standard REST operations."
    },
    "RULE_WEAK_TOKEN_USAGE": {
        "exploit": "curl -X {method} \"http://api.target.local{path}?api_key=somekey\"",
        "verify": "Ensure the API Key is only validated when supplied in the Authorization or custom header (e.g. X-API-KEY)."
    },
    "RULE_NO_INPUT_VALIDATION": {
        "exploit": "curl -X {method} \"http://api.target.local{path}?id=text_where_int_required\"",
        "verify": "Confirm boundary checking is active. Invalid parameters must trigger a validation error (HTTP 422 Unprocessable)."
    },
    "RULE_MISSING_ENUM_CONSTRAINTS": {
        "exploit": "curl -X {method} \"http://api.target.local{path}?status=unknown_state\"",
        "verify": "Define explicit OpenAPI `enum` constraints. Verify inputs match specified schemas."
    },
    "RULE_INFO_EXPOSURE_HEADERS": {
        "exploit": "curl -i -X {method} \"http://api.target.local{path}\"",
        "verify": "Check server headers for platform leakage (e.g., Server, X-Powered-By). Strip these in the Gateway proxy."
    },
    "RULE_PUBLIC_ADMIN_PANEL": {
        "exploit": "curl -X {method} \"http://api.target.local{path}\" (Attempt to load administrative page)",
        "verify": "Ensure administrative endpoints are restricted to specific corporate VPN subnets and check admin session tokens."
    },
    "RULE_INSECURE_IDOR_RISK": {
        "exploit": "curl -X {method} \"http://api.target.local{path}\" (Sweeping integer values)",
        "verify": "Validate that the user context in the session matches the ownership identifier of the requested path resource."
    }
}

# Dynamic circular SVG health gauge
def render_health_gauge(score):
    if score >= 80:
        color = "#10b981" # Emerald Green
    elif score >= 60:
        color = "#f59e0b" # Amber Yellow
    else:
        color = "#ef4444" # Rose Red
        
    svg = f"""
    <div style="display: flex; justify-content: center; align-items: center; padding: 1.2rem 0;">
        <svg width="180" height="180" viewBox="0 0 160 160">
            <!-- Background track -->
            <circle cx="80" cy="80" r="68" fill="none" stroke="#1e293b" stroke-width="12" />
            <!-- Glowing stroke effect -->
            <circle cx="80" cy="80" r="68" fill="none" stroke="{color}" stroke-width="12" 
                    stroke-dasharray="427" stroke-dashoffset="{427 - (427 * score / 100)}" 
                    stroke-linecap="round" transform="rotate(-90 80 80)"
                    filter="drop-shadow(0px 0px 8px {color}88)"
                    style="transition: stroke-dashoffset 1s ease-in-out;" />
            <!-- Score text -->
            <text x="80" y="78" text-anchor="middle" fill="#ffffff" font-family="'Outfit', sans-serif" font-weight="800" font-size="34">{score}</text>
            <text x="80" y="104" text-anchor="middle" fill="#94a3b8" font-family="'Outfit', sans-serif" font-weight="700" font-size="10" letter-spacing="1.5">SECURITY SCORE</text>
        </svg>
    </div>
    """
    return svg

# Helper to check backend status
def get_backend_status():
    try:
        response = requests.get(API_URL, timeout=1.0)
        return response.status_code == 200
    except Exception:
        return False

# Initialize database schemas
init_db()

# Application Title Block
st.markdown("""
    <div class="main-header">
        <h1>🛡️ AI-Driven API Security Review Agent</h1>
        <p>DevSecOps Static Analysis & AI Explainer mapped to OWASP API Security Top 10</p>
    </div>
""", unsafe_allow_html=True)

# Sidebar Navigation
st.sidebar.image("https://img.icons8.com/color/96/shield.png", width=70)
st.sidebar.title("Agent Console")
app_mode = st.sidebar.radio(
    "Choose Action", 
    [
        "Upload & Scan Spec", 
        "Comparative Scan Analytics", 
        "CI/CD Pipeline Generator", 
        "Scan History & Insights", 
        "OWASP API Top 10 Reference", 
        "Project Architecture Docs"
    ]
)

backend_alive = get_backend_status()
if backend_alive:
    st.sidebar.success("🟢 API Backend: Connected")
else:
    st.sidebar.warning("🟡 API Backend: Offline (Local Fallback)")

# ----------------- ACTION 1: UPLOAD & SCAN SPEC -----------------
if app_mode == "Upload & Scan Spec":
    st.header("Upload API Specification")
    st.write("Submit Swagger 2.0 or OpenAPI 3.0 specifications to parse routes, assess risk scores, and view interactive threat remediation guidelines.")
    
    uploaded_file = st.file_uploader(
        "Select JSON or YAML specification (e.g. swagger.json, openapi.yaml)", 
        type=["json", "yaml", "yml"]
    )
    
    if uploaded_file is not None:
        file_details = {"File Name": uploaded_file.name, "File Type": uploaded_file.type}
        st.json(file_details)
        
        if st.button("🚀 Execute Security Analysis", type="primary"):
            with st.spinner("Multi-agent system parsing specs and generating risk assessments..."):
                scan_id = None
                
                # Check backend state
                if backend_alive:
                    try:
                        files = {"file": (uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type)}
                        res = requests.post(f"{API_URL}/scan", files=files)
                        if res.status_code == 200:
                            scan_id = res.json().get("scan_id")
                        else:
                            st.error(f"Backend Scan Error: {res.json().get('detail')}")
                    except Exception as e:
                        st.error(f"Failed to communicate with API server: {e}. Defaulting to local run...")
                
                # Local Fallback
                if not scan_id:
                    try:
                        upload_dir = Path("uploads")
                        upload_dir.mkdir(exist_ok=True)
                        file_path = upload_dir / uploaded_file.name
                        file_path.write_bytes(uploaded_file.getvalue())
                        
                        spec_id = save_specification(
                            filename=uploaded_file.name,
                            content_type=uploaded_file.type or "application/octet-stream",
                            file_path=str(file_path)
                        )
                        
                        scan_id = run_security_scan(
                            file_path=str(file_path),
                            filename=uploaded_file.name,
                            spec_id=spec_id
                        )
                        st.success("Local analyzer completed the scan successfully!")
                    except Exception as e:
                        st.error(f"Local static review engine failed: {e}")
                
                if scan_id:
                    st.session_state["active_scan_id"] = scan_id
                    st.success(f"Scan Finished! Reference ID: #{scan_id}")
                    st.balloons()
                    
    # Render Scan results
    if "active_scan_id" in st.session_state:
        scan_id = st.session_state["active_scan_id"]
        
        scan_meta = get_scan(scan_id)
        findings = get_scan_findings(scan_id)
        reports = get_scan_reports(scan_id)
        
        if scan_meta:
            st.markdown("---")
            
            # Layout Header with health indicator & metrics
            col_gauge, col_metrics = st.columns([1, 2])
            
            with col_gauge:
                st.markdown(render_health_gauge(int(scan_meta["overall_score"])), unsafe_allow_html=True)
                
            with col_metrics:
                st.markdown(f"#### Scan Metrics: {scan_meta['filename']} (Ref: #{scan_id})")
                st.markdown(f"**Scan Executed At:** `{scan_meta['started_at']}` | **Endpoints Detected:** `{scan_meta['total_endpoints']}`")
                
                # HTML Metric Cards
                st.markdown(f"""
                    <div class="metric-container">
                        <div class="metric-card critical">
                            <div style="font-weight:600; font-size:0.85rem; letter-spacing:0.5px;">CRITICAL</div>
                            <div class="metric-val">{scan_meta['critical_count']}</div>
                        </div>
                        <div class="metric-card high">
                            <div style="font-weight:600; font-size:0.85rem; letter-spacing:0.5px;">HIGH</div>
                            <div class="metric-val">{scan_meta['high_count']}</div>
                        </div>
                        <div class="metric-card medium">
                            <div style="font-weight:600; font-size:0.85rem; letter-spacing:0.5px;">MEDIUM</div>
                            <div class="metric-val">{scan_meta['medium_count']}</div>
                        </div>
                        <div class="metric-card low">
                            <div style="font-weight:600; font-size:0.85rem; letter-spacing:0.5px;">LOW</div>
                            <div class="metric-val">{scan_meta['low_count']}</div>
                        </div>
                    </div>
                """, unsafe_allow_html=True)
            
            # Export reports section
            st.markdown("<div class='section-title'>📥 Compliance Exporters</div>", unsafe_allow_html=True)
            dl_cols = st.columns(len(reports) if reports else [1])
            for idx, r in enumerate(reports):
                file_path = r["file_path"]
                fmt = r["format"]
                if os.path.exists(file_path):
                    with open(file_path, "rb") as f:
                        data = f.read()
                    file_ext = ".pdf" if fmt == "PDF" else ".md"
                    mime = "application/pdf" if fmt == "PDF" else "text/markdown"
                    with dl_cols[idx]:
                        st.download_button(
                            label=f"Download {fmt} Assessment Log",
                            data=data,
                            file_name=f"api_security_report_{scan_id}{file_ext}",
                            mime=mime,
                            key=f"dl_btn_{fmt}_{idx}"
                        )
            
            # Vulnerability Explorer (Search and Sort filters)
            st.markdown("<div class='section-title'>🔍 Security Explorer & Remediation Sandbox</div>", unsafe_allow_html=True)
            
            filter_col1, filter_col2, filter_col3 = st.columns([2, 1, 1])
            with filter_col1:
                search_query = st.text_input("Search vulnerabilities by path, rule, or description...", "")
            with filter_col2:
                sev_filter = st.selectbox(
                    "Severity Filter", 
                    ["All Levels", "Critical Only", "High Only", "Medium Only", "Low Only"]
                )
            with filter_col3:
                layout_mode = st.radio("Display Layout", ["Detailed Console", "Compact Table Grid"], horizontal=True)
                
            # Filter Logic
            filtered_findings = findings
            if sev_filter != "All Levels":
                level = sev_filter.split(" ")[0].upper()
                filtered_findings = [f for f in filtered_findings if f["severity"].upper() == level]
                
            if search_query:
                q = search_query.lower()
                filtered_findings = [
                    f for f in filtered_findings 
                    if q in f["path"].lower() or q in f["rule_name"].lower() or q in f["description"].lower()
                ]
                
            if not filtered_findings:
                st.info("No findings match the applied filter query.")
            else:
                if layout_mode == "Compact Table Grid":
                    # Display simple dataframe
                    table_data = []
                    for f in filtered_findings:
                        table_data.append({
                            "Severity": f["severity"].upper(),
                            "Endpoint": f"{f['method']} {f['path']}",
                            "Vulnerability Check": f["rule_name"],
                            "OWASP Map": f"{f['owasp_category']} - {f['owasp_title']}",
                            "Score": f["score"]
                        })
                    df_res = pd.DataFrame(table_data)
                    st.dataframe(df_res, use_container_width=True)
                else:
                    # Detailed cards rendering
                    for idx, f in enumerate(filtered_findings, 1):
                        sev = f["severity"].upper()
                        
                        st.markdown(f"""
                            <div class="card">
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
                                    <div>
                                        <span class="badge {sev.lower()}">{sev}</span>
                                        <span style="font-weight: 700; font-size: 1.15rem; margin-left: 8px;">{f['rule_name']}</span>
                                    </div>
                                    <div style="font-size: 0.85rem; color:#94a3b8; font-weight:600;">
                                        Threat Score: <span style="color:#ef4444; font-size:1.1rem;">{f['score']}</span>/100
                                    </div>
                                </div>
                                <div style="margin-bottom: 0.6rem;">
                                    <b>Location:</b> <span class="route-display">{f['method']} {f['path']}</span>
                                </div>
                                <div style="margin-bottom: 0.75rem; font-size: 0.9rem; color: #cbd5e1;">
                                    <b>OWASP Mapping:</b> <code style="color:#f43f5e; font-weight:bold;">{f['owasp_category']}</code> - <i>{f['owasp_title']}</i>
                                </div>
                                <div style="background-color: rgba(15, 23, 42, 0.4); padding: 0.8rem; border-radius: 6px; border-left: 4px solid #64748B; font-size:0.92rem; line-height:1.45;">
                                    <b>Finding Details:</b> {f['description']}
                                </div>
                            </div>
                        """, unsafe_allow_html=True)
                        
                        with st.expander(f"🛠️ View Exploit Sandbox & Remediation Code for Finding #{idx}"):
                            tabs = st.tabs(["💡 AI Explainer & Impact", "🔒 Remediation Snippet", "🧪 Exploit Simulator"])
                            
                            with tabs[0]:
                                st.markdown("##### Threat Scenario & Business Risk")
                                st.write(f.get("explanation", "No explanation available."))
                                
                            with tabs[1]:
                                st.markdown("##### Secure Code Fix")
                                st.markdown(f.get("mitigation", "No code mitigation guidelines."))
                                
                            with tabs[2]:
                                rule_id = f.get("rule_id", "")
                                sim = EXPLOIT_SIMULATION.get(rule_id, {
                                    "exploit": "curl -X {method} \"http://api.target.local{path}\"",
                                    "verify": "Verify authorization and payload filters are active on {method} {path}."
                                })
                                exploit_cmd = sim["exploit"].format(method=f["method"], path=f["path"])
                                verify_cmd = sim["verify"].format(method=f["method"], path=f["path"])
                                
                                st.markdown("##### Attack Simulation Payload (CLI Command)")
                                st.markdown("This mock script shows how an auditor or threat attacker would exploit the vulnerability:")
                                st.code(exploit_cmd, language="bash")
                                
                                st.markdown("##### Post-Remediation Verification check")
                                st.markdown("Execute this command after applying the fix. The response must match the assertions outlined below:")
                                st.code(verify_cmd, language="bash")

# ----------------- ACTION 2: COMPARATIVE SCAN ANALYTICS -----------------
elif app_mode == "Comparative Scan Analytics":
    st.header("Comparative Scan Analytics & Diffs")
    st.write("Select two security reviews from the historical logs to generate a delta report. This helps you track remediation progress, ensure no new security regressions were introduced, and verify which flaws were resolved.")
    
    try:
        scans = get_all_scans()
        if len(scans) < 2:
            st.info("At least two historical scans are required to generate a comparison report. Upload another specification file first!")
        else:
            scan_options = []
            for s in scans:
                scan_options.append({
                    "id": s["id"],
                    "label": f"#{s['id']} - {s['filename']} ({s['started_at'].split('T')[0]}) [Score: {s['overall_score']}]"
                })
            
            df_opt = pd.DataFrame(scan_options)
            
            col_a, col_b = st.columns(2)
            with col_a:
                select_a = st.selectbox("Select Baseline Scan (Scan A)", options=df_opt["id"], format_func=lambda x: df_opt[df_opt["id"] == x]["label"].values[0])
            with col_b:
                select_b = st.selectbox("Select Target Scan (Scan B)", options=df_opt["id"], format_func=lambda x: df_opt[df_opt["id"] == x]["label"].values[0])
                
            if select_a == select_b:
                st.warning("Please select two different scans to compare.")
            else:
                if st.button("Generate Comparative Diff", type="primary"):
                    meta_a = get_scan(select_a)
                    meta_b = get_scan(select_b)
                    
                    if meta_a and meta_b:
                        st.markdown("---")
                        st.subheader("📊 Comparative Scan Summary")
                        
                        score_delta = meta_b["overall_score"] - meta_a["overall_score"]
                        crit_delta = meta_b["critical_count"] - meta_a["critical_count"]
                        high_delta = meta_b["high_count"] - meta_a["high_count"]
                        med_delta = meta_b["medium_count"] - meta_a["medium_count"]
                        low_delta = meta_b["low_count"] - meta_a["low_count"]
                        
                        # Comparison Metrics Layout
                        col1, col2, col3, col4, col5 = st.columns(5)
                        
                        with col1:
                            delta_color = "color:#10b981;" if score_delta >= 0 else "color:#ef4444;"
                            delta_sign = "+" if score_delta >= 0 else ""
                            st.markdown(f"""
                                <div class="metric-card" style="border-top-color:#3b82f6;">
                                    <div style="font-weight:600; font-size:0.85rem; color:#94a3b8;">SCORE DELTA</div>
                                    <div class="metric-val" style="color:#ffffff;">{meta_b['overall_score']}</div>
                                    <div style="font-size:0.85rem; font-weight:bold; {delta_color}">{delta_sign}{score_delta:.1f} pts</div>
                                </div>
                            """, unsafe_allow_html=True)
                            
                        with col2:
                            c_color = "color:#10b981;" if crit_delta <= 0 else "color:#ef4444;"
                            c_sign = "" if crit_delta <= 0 else "+"
                            st.markdown(f"""
                                <div class="metric-card critical">
                                    <div style="font-weight:600; font-size:0.85rem; color:#94a3b8;">CRITICALS</div>
                                    <div class="metric-val">{meta_b['critical_count']}</div>
                                    <div style="font-size:0.85rem; font-weight:bold; {c_color}">{c_sign}{crit_delta}</div>
                                </div>
                            """, unsafe_allow_html=True)
                            
                        with col3:
                            h_color = "color:#10b981;" if high_delta <= 0 else "color:#ef4444;"
                            h_sign = "" if high_delta <= 0 else "+"
                            st.markdown(f"""
                                <div class="metric-card high">
                                    <div style="font-weight:600; font-size:0.85rem; color:#94a3b8;">HIGHS</div>
                                    <div class="metric-val">{meta_b['high_count']}</div>
                                    <div style="font-size:0.85rem; font-weight:bold; {h_color}">{h_sign}{high_delta}</div>
                                </div>
                            """, unsafe_allow_html=True)
                            
                        with col4:
                            m_color = "color:#10b981;" if med_delta <= 0 else "color:#ef4444;"
                            m_sign = "" if med_delta <= 0 else "+"
                            st.markdown(f"""
                                <div class="metric-card medium">
                                    <div style="font-weight:600; font-size:0.85rem; color:#94a3b8;">MEDIUMS</div>
                                    <div class="metric-val">{meta_b['medium_count']}</div>
                                    <div style="font-size:0.85rem; font-weight:bold; {m_color}">{m_sign}{med_delta}</div>
                                </div>
                            """, unsafe_allow_html=True)
                            
                        with col5:
                            l_color = "color:#10b981;" if low_delta <= 0 else "color:#ef4444;"
                            l_sign = "" if low_delta <= 0 else "+"
                            st.markdown(f"""
                                <div class="metric-card low">
                                    <div style="font-weight:600; font-size:0.85rem; color:#94a3b8;">LOWS</div>
                                    <div class="metric-val">{meta_b['low_count']}</div>
                                    <div style="font-size:0.85rem; font-weight:bold; {l_color}">{l_sign}{low_delta}</div>
                                </div>
                            """, unsafe_allow_html=True)
                            
                        # Chart layout
                        st.markdown("<div class='section-title'>📈 Comparative Visualization</div>", unsafe_allow_html=True)
                        
                        categories = ["Critical", "High", "Medium", "Low"]
                        counts_a = [meta_a['critical_count'], meta_a['high_count'], meta_a['medium_count'], meta_a['low_count']]
                        counts_b = [meta_b['critical_count'], meta_b['high_count'], meta_b['medium_count'], meta_b['low_count']]
                        
                        fig, ax = plt.subplots(figsize=(8, 3.5))
                        x = np.arange(len(categories))
                        width = 0.3
                        
                        ax.bar(x - width/2, counts_a, width, label=f"Scan A (#{select_a})", color="#64748b", alpha=0.9)
                        ax.bar(x + width/2, counts_b, width, label=f"Scan B (#{select_b})", color="#06b6d4", alpha=0.9)
                        
                        ax.set_ylabel("Findings Count", color="#ffffff")
                        ax.set_title("Vulnerability Severity Comparison", color="#ffffff", fontsize=11, pad=12)
                        ax.set_xticks(x)
                        ax.set_xticklabels(categories, color="#ffffff")
                        ax.legend(facecolor="#1e293b", edgecolor="none", labelcolor="#ffffff")
                        
                        fig.patch.set_facecolor('#0b0f19')
                        ax.set_facecolor('#0b0f19')
                        ax.spines['bottom'].set_color('#334155')
                        ax.spines['left'].set_color('#334155')
                        ax.spines['top'].set_color('none')
                        ax.spines['right'].set_color('none')
                        ax.tick_params(colors='#94a3b8')
                        ax.yaxis.grid(True, linestyle='--', alpha=0.1)
                        plt.tight_layout()
                        st.pyplot(fig)
                        
                        # Detailed listing of findings in B that are new, or findings resolved
                        st.markdown("<div class='section-title'>📋 Audit Summary Diff</div>", unsafe_allow_html=True)
                        
                        findings_a = get_scan_findings(select_a)
                        findings_b = get_scan_findings(select_b)
                        
                        sig_a = {f"{f['method']}_{f['path']}_{f['rule_id']}" for f in findings_a}
                        sig_b = {f"{f['method']}_{f['path']}_{f['rule_id']}" for f in findings_b}
                        
                        resolved_signatures = sig_a - sig_b
                        new_signatures = sig_b - sig_a
                        
                        col_new, col_resolved = st.columns(2)
                        
                        with col_new:
                            st.markdown("#### 🚨 New Vulnerabilities Introduced")
                            if not new_signatures:
                                st.success("No new vulnerabilities introduced in Scan B!")
                            else:
                                for sig in new_signatures:
                                    method, path, rule_id = sig.split("_", 2)
                                    st.error(f"**{method} {path}** - `{rule_id}`")
                                    
                        with col_resolved:
                            st.markdown("#### ✅ Vulnerabilities Resolved")
                            if not resolved_signatures:
                                st.info("No previously flagged vulnerabilities were resolved in Scan B.")
                            else:
                                for sig in resolved_signatures:
                                    method, path, rule_id = sig.split("_", 2)
                                    st.success(f"**{method} {path}** - `{rule_id}`")
                                    
    except Exception as e:
        st.error(f"Error loading comparison datasets: {e}")

# ----------------- ACTION 3: CI/CD PIPELINE GENERATOR -----------------
elif app_mode == "CI/CD Pipeline Generator":
    st.header("CI/CD Pipeline Configurations")
    st.write("Generate automated pipeline configurations to integrate the API Security Review Agent as a static code analysis check (SAST) in your software development pipeline (CI/CD). This keeps security guardrails active on every commit or pull request.")
    
    # Custom configurations
    st.markdown("<div class='section-title'>⚙️ Pipeline Configuration Parameters</div>", unsafe_allow_html=True)
    spec_path = st.text_input("Path to API Specification file in repository:", "openapi.yaml")
    
    fail_sev = st.selectbox(
        "Fail build on Severity Threshold:",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    )
    
    report_format = st.selectbox(
        "Auto-Generate Reports:",
        ["PDF", "Markdown", "Both"]
    )
    
    st.markdown("<div class='section-title'>🛠️ Automation Snippets</div>", unsafe_allow_html=True)
    tabs = st.tabs(["GitHub Actions", "GitLab CI/CD", "Local Docker Executable"])
    
    # Compile YAML configs dynamically
    with tabs[0]:
        st.markdown("##### GitHub Actions Workflow file")
        st.markdown("Create a file at `.github/workflows/api-security-scan.yml` with the following content:")
        
        gh_yml = f"""name: API Static Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  api-sec-scan:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v3

      - name: Set up Python 3.10
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install Dependencies
        run: |
          pip install requests pydantic ruamel.yaml prance reportlab langgraph slowapi

      - name: Run API Security Scanner
        env:
          FAIL_SEVERITY: "{fail_sev}"
          SPEC_PATH: "{spec_path}"
          REPORT_FORMAT: "{report_format}"
        run: |
          # Runs the scan engine CLI
          python -m app.backend_api scan --file "$SPEC_PATH" --fail-on "$FAIL_SEVERITY" --format "$REPORT_FORMAT"
"""
        st.code(gh_yml, language="yaml")
        
    with tabs[1]:
        st.markdown("##### GitLab CI Configuration Snippet")
        st.markdown("Append this job definition block to your `.gitlab-ci.yml` pipeline file:")
        
        gl_yml = f"""stages:
  - test
  - security

api_security_static_scan:
  stage: security
  image: python:3.10-slim
  variables:
    SPEC_PATH: "{spec_path}"
    FAIL_SEVERITY: "{fail_sev}"
    REPORT_FORMAT: "{report_format}"
  before_script:
    - pip install -r requirements.txt
  script:
    - python -m app.backend_api scan --spec "$SPEC_PATH" --fail-on "$FAIL_SEVERITY" --format "$REPORT_FORMAT"
  artifacts:
    name: "api_security_report"
    when: always
    paths:
      - reports/
"""
        st.code(gl_yml, language="yaml")
        
    with tabs[2]:
        st.markdown("##### Run Local Docker Scan CLI")
        st.markdown("Run this terminal command in your repository workspace root to scan locally using the Docker daemon container:")
        
        docker_cmd = f"""docker run --rm \\
  -v "$(pwd)":/app \\
  -w /app \\
  -e SPEC_PATH="/app/{spec_path}" \\
  -e FAIL_SEVERITY="{fail_sev}" \\
  suryaprasath41/api-security-agent:latest \\
  python -m app.backend_api scan --file "/app/{spec_path}" --fail-on "{fail_sev}"
"""
        st.code(docker_cmd, language="bash")

# ----------------- ACTION 4: SCAN HISTORY & INSIGHTS -----------------
elif app_mode == "Scan History & Insights":
    st.header("Historical Scan Metrics")
    st.write("Analyze and review the statistics of scans run historically in this workspace.")
    
    try:
        scans = get_all_scans()
        if not scans:
            st.info("No scan records found in database. Scan a spec file first!")
        else:
            df = pd.DataFrame(scans)
            
            # Reorder
            df_display = df[["id", "filename", "status", "total_endpoints", "overall_score", "critical_count", "high_count", "medium_count", "low_count", "started_at"]].copy()
            df_display.columns = ["Scan ID", "Filename", "Status", "APIs", "Health Score", "Critical", "High", "Medium", "Low", "Scan Date"]
            
            # Render styled history table
            st.markdown("<div class='section-title'>📋 History Log</div>", unsafe_allow_html=True)
            st.dataframe(df_display, use_container_width=True)
            
            st.markdown("<div class='section-title'>📈 Security Trend Graph</div>", unsafe_allow_html=True)
            
            # Draw line chart for score trend
            df_sorted = df.sort_values(by="id")
            fig, ax = plt.subplots(figsize=(8, 3))
            ax.plot(df_sorted["id"].astype(str), df_sorted["overall_score"], marker='o', color='#3b82f6', linewidth=2, label="Security Health Score")
            
            ax.set_ylabel("Health Score", color="#ffffff")
            ax.set_xlabel("Scan ID", color="#ffffff")
            ax.set_ylim(0, 105)
            ax.set_title("Overall Security Score Trend", color="#ffffff", pad=12)
            
            fig.patch.set_facecolor('#0b0f19')
            ax.set_facecolor('#0b0f19')
            ax.spines['bottom'].set_color('#334155')
            ax.spines['left'].set_color('#334155')
            ax.spines['top'].set_color('none')
            ax.spines['right'].set_color('none')
            ax.tick_params(colors='#94a3b8')
            ax.yaxis.grid(True, linestyle='--', alpha=0.1)
            plt.tight_layout()
            st.pyplot(fig)
            
            # Select past scan
            st.markdown("<div class='section-title'>🛠️ Load Historical Findings</div>", unsafe_allow_html=True)
            scan_selection = st.selectbox("Select Scan ID to load into Active Spec Results View", df_display["Scan ID"].tolist())
            if st.button("Load Scan Data", type="primary"):
                st.session_state["active_scan_id"] = scan_selection
                st.success(f"Scan #{scan_selection} loaded. Switch navigation to 'Upload & Scan Spec' to inspect details.")
                st.balloons()
                
    except Exception as e:
        st.error(f"Error loading scan records from database: {e}")

# ----------------- ACTION 5: OWASP API TOP 10 REFERENCE -----------------
elif app_mode == "OWASP API Top 10 Reference":
    st.header("OWASP API Security Top 10 Reference Sheet")
    st.write("Learn about the OWASP API Security vulnerabilities checked by our analyzer rules.")
    
    owasp_items = {
        "API1:2023 - Broken Object Level Authorization (BOLA)": {
            "Description": "Endpoints expose object keys directly. Attackers manipulate resource identifiers in the URL (e.g. `/api/v1/accounts/123` to `/api/v1/accounts/124`) to fetch other user profiles, bypassing proper authorization limits.",
            "Example Vulnerability": "GET `/users/{userId}/profile` without verifying if the requesting session token owner matches `{userId}`.",
            "Mitigation": "Enforce fine-grained user checks on the database query level (e.g., matching the resource owner to the token context ID). Utilize cryptographically secure UUIDs instead of auto-incremented database IDs."
        },
        "API2:2023 - Broken Authentication": {
            "Description": "Incorrect implementation of session cookies, token validations, or credential checks. Attackers can brute-force identifiers, forge keys, or exploit weak token parsing blocks to assume identities.",
            "Example Vulnerability": "Exposing key parameters inside plain URL queries or missing token signatures validation.",
            "Mitigation": "Implement bearer token authorization header (OAuth2 JWT) with signature algorithms validation. Enforce password complexity and multi-factor credentials check."
        },
        "API3:2023 - Broken Object Property Level Authorization": {
            "Description": "Combines Mass Assignment and Excessive Data Exposure. APIs return complete database object JSON outputs (e.g. including roles, internal passwords) trusting the client UI to redact it, or accept client inputs to overwrite server-managed properties.",
            "Example Vulnerability": "POST `/users/update` allowing a payload like `{'role': 'admin'}` to escalate user privileges.",
            "Mitigation": "Implement strong validation schemas (Pydantic / DTOs). Use strict filters for serializing out databases data, preventing raw database dump exposes."
        },
        "API4:2023 - Unrestricted Resource Consumption": {
            "Description": "Lack of constraints on resource allocations (such as CPU, database queries, memory, disk size, or rate limiters) allowing attackers to trigger application freezes or massive cloud bill charges.",
            "Example Vulnerability": "Allowing client uploads of unlimited payload sizes or infinite page list retrievals (`GET /items?limit=999999`).",
            "Mitigation": "Integrate API rate limit limits, restrict payload limits (e.g., maximum file sizes), enforce strict pagination defaults (e.g. limit=100 max), and apply regex timeouts."
        },
        "API5:2023 - Broken Function Level Authorization": {
            "Description": "Authorization limits only validate path prefixes, allowing non-admin users to trigger admin functionality by changing the HTTP method (e.g. modifying GET to DELETE on an admin route).",
            "Example Vulnerability": "Letting any authenticated user call `DELETE /admin/roles/1` because the filter only checks for authenticated users, not role types.",
            "Mitigation": "Configure explicit, granular role validations matching the exact combination of HTTP method and path pattern on every handler route."
        },
        "API8:2023 - Security Misconfiguration": {
            "Description": "Exposure of debug markers, plain HTTP servers, verbose stack traces, wildcards in CORS origins, or default values that provide attackers inside knowledge to pivot operations.",
            "Example Vulnerability": "Exposing CORS headers `Access-Control-Allow-Origin: *` while passing credentials, or returning stack traces.",
            "Mitigation": "Configure strict CORS whitelists, use secure headers, disable plaintext HTTP transport in production (enforce TLS), and capture all exceptions cleanly."
        },
        "API10:2023 - Unsafe Consumption of APIs / Injection": {
            "Description": "APIs trust data received from client query parameters or third-party APIs without sanitization. Vulnerable to SQL injection, shell script executions, or content manipulation.",
            "Example Vulnerability": "Passing client parameters directly to database cursors: `cursor.execute(f'SELECT * FROM users WHERE name = {user_input}')`.",
            "Mitigation": "Utilize parameterized statements, use secure ORM platforms, and filter inputs with strict regex schemas."
        }
    }
    
    for title, details in owasp_items.items():
        with st.expander(title):
            st.markdown(f"**Description:** {details['Description']}")
            st.markdown(f"**Vulnerable Endpoint Example:** `{details['Example Vulnerability']}`")
            st.markdown(f"**Prevention Strategy:** {details['Mitigation']}")

# ----------------- ACTION 6: PROJECT ARCHITECTURE DOCS -----------------
elif app_mode == "Project Architecture Docs":
    st.header("Project System Architecture & Workflow")
    st.write("Overview of the underlying components, agent roles, and information pipelines.")
    
    st.markdown("""
    ### Agentic Workflow Overview
    
    The system follows a modular agent design orchestrated sequentially. Every agent is modeled as a node on a shared state graph.
    
    1. **Parser Agent**: Extracts endpoints, parameters, request body models, and base server protocols from the JSON/YAML file.
    2. **Rule Engine Agent**: Applies 20 code checks on parsed components and identifies structural gaps.
    3. **OWASP Mapping Agent**: Correlates discoveries to OWASP API Security Top 10 vulnerabilities.
    4. **LLM Explainer Agent**: Invokes LLMs (OpenAI, Ollama, or local template engine) to describe risks and generate styled code fixes.
    5. **Risk Assessment Agent**: Calculates threat severity scores via $Score = Severity \\times Exploitability \\times Exposure$ and evaluates overall health index.
    6. **Reporting Agent**: Compiles Markdown and PDF logs, writing files to the disk and database.
    
    ### System Architecture Layers
    
    - **Presentation Layer**: Streamlit web dashboard.
    - **Service & Processing Layer**: FastAPI routing endpoint handler.
    - **Agentic Logic Layer**: LangGraph StateGraph nodes.
    - **Storage Layer**: SQLite relational database.
    """)
    
    st.subheader("Information Pipeline Diagram")
    st.code("""
    [Upload Spec] ──> [Parser Agent] ──> [Rule Engine Agent] (20 Checks)
                                                 │
                                                 ▼
    [Risk Assessment] <── [LLM Explainer] <── [OWASP Mapping Agent]
            │
            ▼
    [Reporting Agent] ──> [Save to SQLite DB] & [Generate PDF/Markdown]
    """, language="text")
