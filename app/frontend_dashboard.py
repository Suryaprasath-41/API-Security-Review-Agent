import streamlit as st
import requests
import os
import sqlite3
import pandas as pd
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
    page_title="Intelligent API Security Review Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Premium Styling
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    
    .main-header {
        background: linear-gradient(135deg, #1E3A8A 0%, #3B82F6 100%);
        padding: 2.5rem;
        border-radius: 12px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
    }
    
    .main-header h1 {
        font-weight: 700;
        font-size: 2.5rem;
        margin: 0;
        color: white;
    }
    
    .main-header p {
        font-size: 1.1rem;
        font-weight: 300;
        opacity: 0.9;
        margin-top: 0.5rem;
    }
    
    .card {
        background: white;
        padding: 1.5rem;
        border-radius: 8px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
        border: 1px solid #F1F5F9;
        margin-bottom: 1.5rem;
    }
    
    .metric-container {
        display: flex;
        justify-content: space-around;
        margin-bottom: 2rem;
    }
    
    .metric-card {
        background: #F8FAFC;
        padding: 1.2rem;
        border-radius: 8px;
        text-align: center;
        width: 22%;
        border-top: 5px solid #64748B;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    
    .metric-card.critical { border-top-color: #EF4444; }
    .metric-card.high { border-top-color: #F97316; }
    .metric-card.medium { border-top-color: #F59E0B; }
    .metric-card.low { border-top-color: #3B82F6; }
    
    .metric-val {
        font-size: 2rem;
        font-weight: 700;
        margin-top: 0.2rem;
    }
    
    .badge {
        padding: 0.25rem 0.6rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        color: white;
        display: inline-block;
    }
    .badge.critical { background-color: #EF4444; }
    .badge.high { background-color: #F97316; }
    .badge.medium { background-color: #F59E0B; }
    .badge.low { background-color: #3B82F6; }
    
    .route-display {
        font-family: 'Courier New', Courier, monospace;
        font-weight: bold;
        background: #F1F5F9;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        color: #0F172A;
    }
    </style>
""", unsafe_allow_html=True)

# Helper to check backend status
def get_backend_status():
    try:
        response = requests.get(API_URL, timeout=1.0)
        return response.status_code == 200
    except Exception:
        return False

# Initialize database if missing (dual mode safety)
init_db()

# Application Title Block
st.markdown("""
    <div class="main-header">
        <h1>AI-Driven API Security Review Agent</h1>
        <p>DevSecOps Static Analysis & AI Explainer mapped to OWASP API Top 10</p>
    </div>
""", unsafe_allow_html=True)

# Sidebar Navigation
st.sidebar.image("https://img.icons8.com/color/96/shield.png", width=80)
st.sidebar.title("Navigation")
app_mode = st.sidebar.radio(
    "Choose Mode", 
    ["Upload & Scan Spec", "Scan History & Insights", "OWASP API Top 10 Reference", "Project Architecture Docs"]
)

backend_alive = get_backend_status()
if backend_alive:
    st.sidebar.success("🟢 API Backend Service: Connected")
else:
    st.sidebar.warning("🟡 API Backend Offline (Running Local Mode)")

# ----------------- MODE 1: UPLOAD & SCAN SPEC -----------------
if app_mode == "Upload & Scan Spec":
    st.header("Upload OpenAPI/Swagger Specification")
    uploaded_file = st.file_uploader("Upload JSON or YAML file (e.g. swagger.json, openapi.yaml)", type=["json", "yaml", "yml"])
    
    if uploaded_file is not None:
        file_details = {"FileName": uploaded_file.name, "FileType": uploaded_file.type}
        st.write(file_details)
        
        if st.button("🚀 Run Agent Security Review", type="primary"):
            with st.spinner("LangGraph multi-agent parsing and reviewing specification..."):
                scan_id = None
                
                # Dynamic Mode execution
                if backend_alive:
                    try:
                        files = {"file": (uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type)}
                        res = requests.post(f"{API_URL}/scan", files=files)
                        if res.status_code == 200:
                            scan_id = res.json().get("scan_id")
                        else:
                            st.error(f"Backend Scan Error: {res.json().get('detail')}")
                    except Exception as e:
                        st.error(f"Failed to communicate with backend: {e}. Attempting local execution...")
                
                # Local Fallback Execution
                if not scan_id:
                    try:
                        # Save file locally
                        upload_dir = Path("uploads")
                        upload_dir.mkdir(exist_ok=True)
                        file_path = upload_dir / uploaded_file.name
                        file_path.write_bytes(uploaded_file.getvalue())
                        
                        # Register in DB
                        spec_id = save_specification(
                            filename=uploaded_file.name,
                            content_type=uploaded_file.type or "application/octet-stream",
                            file_path=str(file_path)
                        )
                        
                        # Run workflow
                        scan_id = run_security_scan(
                            file_path=str(file_path),
                            filename=uploaded_file.name,
                            spec_id=spec_id
                        )
                        st.success("Local security workflow ran successfully!")
                    except Exception as e:
                        st.error(f"Local workflow execution failed: {e}")
                
                if scan_id:
                    st.session_state["active_scan_id"] = scan_id
                    st.success(f"Scan Completed! Scan Reference ID: #{scan_id}")
                    st.balloons()
                    
    # Render Active Scan Results if present
    if "active_scan_id" in st.session_state:
        scan_id = st.session_state["active_scan_id"]
        
        # Load details
        scan_meta = get_scan(scan_id)
        findings = get_scan_findings(scan_id)
        reports = get_scan_reports(scan_id)
        
        if scan_meta:
            st.markdown("---")
            st.subheader(f"Analysis Results for: {scan_meta['filename']} (Scan #{scan_id})")
            
            # Health score and status banner
            health_color = "green" if scan_meta["overall_score"] >= 80 else "orange" if scan_meta["overall_score"] >= 60 else "red"
            st.markdown(f"""
                <div style="background-color: #F8FAFC; border-left: 6px solid {health_color}; padding: 1.2rem; border-radius: 6px; margin-bottom: 1.5rem;">
                    <h4 style="margin:0; color:#334155;">Overall Security Health Score</h4>
                    <h2 style="margin: 0.2rem 0 0 0; color:#1E3A8A;"><b>{scan_meta['overall_score']} / 100</b></h2>
                </div>
            """, unsafe_allow_html=True)
            
            # Metric Counts HTML representation
            st.markdown(f"""
                <div class="metric-container">
                    <div class="metric-card critical">
                        <div style="color: #EF4444; font-weight:600; font-size:0.9rem;">CRITICAL</div>
                        <div class="metric-val" style="color: #EF4444;">{scan_meta['critical_count']}</div>
                    </div>
                    <div class="metric-card high">
                        <div style="color: #F97316; font-weight:600; font-size:0.9rem;">HIGH</div>
                        <div class="metric-val" style="color: #F97316;">{scan_meta['high_count']}</div>
                    </div>
                    <div class="metric-card medium">
                        <div style="color: #F59E0B; font-weight:600; font-size:0.9rem;">MEDIUM</div>
                        <div class="metric-val" style="color: #F59E0B;">{scan_meta['medium_count']}</div>
                    </div>
                    <div class="metric-card low">
                        <div style="color: #3B82F6; font-weight:600; font-size:0.9rem;">LOW</div>
                        <div class="metric-val" style="color: #3B82F6;">{scan_meta['low_count']}</div>
                    </div>
                </div>
            """, unsafe_allow_html=True)
            
            # Split Layout: Charts & Export Buttons
            col1, col2 = st.columns([2, 1])
            with col1:
                # Severity Distribution Chart
                labels = ["Critical", "High", "Medium", "Low"]
                counts = [scan_meta['critical_count'], scan_meta['high_count'], scan_meta['medium_count'], scan_meta['low_count']]
                
                # Check if there are findings
                if sum(counts) > 0:
                    fig, ax = plt.subplots(figsize=(6, 3))
                    colors_list = ["#EF4444", "#F97316", "#F59E0B", "#3B82F6"]
                    # filter out zeroes
                    final_labels = [l for i, l in enumerate(labels) if counts[i] > 0]
                    final_counts = [c for c in counts if c > 0]
                    final_colors = [colors_list[i] for i, c in enumerate(counts) if c > 0]
                    
                    ax.pie(final_counts, labels=final_labels, colors=final_colors, autopct='%1.1f%%', startangle=90, textprops={'fontsize': 8})
                    ax.axis('equal')
                    fig.patch.set_facecolor('#FFFFFF')
                    st.markdown("##### Findings Severity Distribution")
                    st.pyplot(fig)
                else:
                    st.info("No findings to chart. The API specification is clean!")
            
            with col2:
                st.markdown("##### Export Security Reports")
                st.write("Download the compliance assessment report to share with developers and security administrators.")
                
                for r in reports:
                    file_path = r["file_path"]
                    fmt = r["format"]
                    
                    if os.path.exists(file_path):
                        with open(file_path, "rb") as f:
                            data = f.read()
                        
                        btn_label = f"📥 Download {fmt} Report"
                        file_ext = ".pdf" if fmt == "PDF" else ".md"
                        mime_type = "application/pdf" if fmt == "PDF" else "text/markdown"
                        
                        st.download_button(
                            label=btn_label,
                            data=data,
                            file_name=f"api_security_report_{scan_id}{file_ext}",
                            mime=mime_type
                        )
                        st.write("")
            
            # Findings Table
            st.subheader("Discovered Vulnerabilities & Mitigations")
            if not findings:
                st.info("No vulnerabilities detected in this scan.")
            else:
                # List findings cleanly
                for idx, f in enumerate(findings, 1):
                    sev = f["severity"].upper()
                    st.markdown(f"""
                        <div class="card">
                            <span class="badge {sev.lower()}">{sev}</span>
                            <span style="font-weight: 700; font-size: 1.15rem; margin-left: 8px;">{f['rule_name']} (Risk Score: {f['score']}/100)</span>
                            <div style="margin-top: 8px;">
                                <b>Location:</b> <span class="route-display">{f['method']} {f['path']}</span>
                            </div>
                            <div style="margin-top: 8px;">
                                <b>OWASP Category:</b> <b>{f['owasp_category']}</b> - {f['owasp_title']}
                            </div>
                            <div style="margin-top: 10px; background-color:#FAF9F6; padding: 10px; border-radius: 4px; border-left: 4px solid #64748B;">
                                <b>Description:</b> {f['description']}
                            </div>
                        </div>
                    """, unsafe_allow_html=True)
                    
                    # Inside the loop, render the AI explainer and code snippet inside standard st expanders
                    with st.expander(f"🔍 Click to inspect AI Threat Explainer & Code Mitigations for #{idx}"):
                        st.markdown("##### AI Explainer & Business Impact")
                        st.write(f.get("explanation", "No AI analysis performed."))
                        st.markdown("##### Actionable Code Remediation")
                        st.markdown(f.get("mitigation", "No mitigation rules defined."))

# ----------------- MODE 2: SCAN HISTORY & INSIGHTS -----------------
elif app_mode == "Scan History & Insights":
    st.header("Vulnerability Scans History Log")
    st.write("Browse all historical scans, load past metrics, and download previously compiled reports.")
    
    try:
        scans = get_all_scans()
        if not scans:
            st.info("No scan history discovered. Upload and scan a file first!")
        else:
            df = pd.DataFrame(scans)
            # Reorder & rename columns for display
            df_display = df[["id", "filename", "status", "total_endpoints", "overall_score", "critical_count", "high_count", "medium_count", "low_count", "started_at"]].copy()
            df_display.columns = ["Scan ID", "Filename", "Status", "Total APIs", "Health Score", "Criticals", "Highs", "Mediums", "Lows", "Scan Date"]
            
            st.dataframe(df_display, use_container_width=True)
            
            # Selection box to load a scan
            scan_selection = st.selectbox("Select Scan ID to load details", df_display["Scan ID"].tolist())
            if st.button("Load Selected Scan"):
                st.session_state["active_scan_id"] = scan_selection
                st.rerun()
    except Exception as e:
        st.error(f"Failed to read from history: {e}")

# ----------------- MODE 3: OWASP API TOP 10 REFERENCE -----------------
elif app_mode == "OWASP API Top 10 Reference":
    st.header("OWASP API Security Top 10 (2023) Quick Reference")
    st.write("A student review guide explaining the industry-standard vulnerabilities targeted by this agent.")
    
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

# ----------------- MODE 4: PROJECT ARCHITECTURE DOCS -----------------
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
    
    # Render flowchart diagram
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
