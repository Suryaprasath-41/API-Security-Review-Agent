import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
from app.config import REPORT_DIR
from app.database import save_report
from app.utils.pdf_generator import generate_pdf_report

class ReportAgent:
    """
    Assembles final security evaluation documents, writing both Markdown and PDF formats
    to local storage and mapping their metadata records into the database.
    """
    def __init__(self):
        self.report_dir = Path(REPORT_DIR)
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def generate_reports(self, scan_id: int, scan_meta: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, str]:
        # Generate Markdown Report path
        md_filename = f"scan_{scan_id}_report.md"
        md_path = self.report_dir / md_filename
        
        # Generate PDF Report path
        pdf_filename = f"scan_{scan_id}_report.pdf"
        pdf_path = self.report_dir / pdf_filename

        # Write Markdown Report content
        self._write_markdown_report(scan_meta, findings, md_path)
        save_report(scan_id, str(md_path), "MARKDOWN")
        
        # Generate PDF Report content
        generate_pdf_report(scan_meta, findings, str(pdf_path))
        save_report(scan_id, str(pdf_path), "PDF")

        return {
            "markdown_report_path": str(md_path),
            "pdf_report_path": str(pdf_path)
        }

    def _write_markdown_report(self, meta: Dict[str, Any], findings: List[Dict[str, Any]], output_path: Path):
        """Generates standard Markdown formatted assessment reports."""
        
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        md_content = f"""# API Security Assessment Report

**Target Specification:** {meta.get('filename')}
**Scan Execution Date:** {now_str}
**Security Health Score:** **{meta.get('overall_score', 100.0)} / 100**
**Total Endpoints Scanned:** {meta.get('total_endpoints', 0)}

---

## Findings Executive Summary

| Risk Level | Finding Count |
| :--- | :--- |
| **Critical** | {meta.get('critical_count', 0)} |
| **High** | {meta.get('high_count', 0)} |
| **Medium** | {meta.get('medium_count', 0)} |
| **Low** | {meta.get('low_count', 0)} |

---

## Detailed Vulnerability Report

"""
        if not findings:
            md_content += "### ✅ No vulnerabilities identified!\nThe security rule engine scanned all routes and configurations and found zero violations. Keep up the good work.\n"
        else:
            for idx, f in enumerate(findings, 1):
                md_content += f"""### {idx}. {f.get('rule_name')} `[{f.get('severity')}]`

- **Endpoint Route:** `{f.get('method')} {f.get('path')}`
- **OWASP API Category:** **{f.get('owasp_category')}** - {f.get('owasp_title')}
- **Risk Score:** {f.get('score')} / 100 (Severity: {f.get('severity')} | Exploitability: {f.get('exploitability')} | Exposure: {f.get('exposure')})

#### 🔍 Vulnerability Description
{f.get('description')}

#### 💡 AI Explainer & Technical Impact
{f.get('explanation')}

#### 🛠️ Code Mitigation Snippet
{f.get('mitigation')}

---
"""
        
        output_path.write_text(md_content, encoding="utf-8")
