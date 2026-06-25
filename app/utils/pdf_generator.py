import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to calculate total page count and add standard headers/footers.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 9)
        self.setFillColor(colors.HexColor("#4A5568"))
        
        # Header (Only on page 2 and later)
        if self._pageNumber > 1:
            self.drawString(54, 750, "API Security Assessment Report")
            self.drawRightString(612 - 54, 750, datetime.now().strftime("%Y-%m-%d"))
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(54, 742, 612 - 54, 742)
            
        # Footer
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(612 - 54, 40, page_text)
        self.drawString(54, 40, "CONFIDENTIAL - Internal Security Review Only")
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 52, 612 - 54, 52)
        
        self.restoreState()

def generate_pdf_report(scan_meta: dict, findings: list, output_path: str):
    """
    Generates a beautifully typeset PDF report using ReportLab.
    """
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=72,
        bottomMargin=72
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=26,
        leading=30,
        textColor=colors.HexColor("#1E3A8A"),
        spaceAfter=15
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#4B5563"),
        spaceAfter=30
    )
    
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#1E3A8A"),
        spaceBefore=15,
        spaceAfter=10,
        keepWithNext=True
    )
    
    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#334155"),
        spaceAfter=8
    )

    code_style = ParagraphStyle(
        'Code_Custom',
        parent=styles['Code'],
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0F172A"),
        backColor=colors.HexColor("#F1F5F9"),
        borderColor=colors.HexColor("#E2E8F0"),
        borderWidth=0.5,
        borderPadding=6,
        spaceBefore=5,
        spaceAfter=5
    )

    severity_colors = {
        "CRITICAL": colors.HexColor("#EF4444"), # Red
        "HIGH": colors.HexColor("#F97316"),     # Orange
        "MEDIUM": colors.HexColor("#F59E0B"),   # Amber
        "LOW": colors.HexColor("#3B82F6")       # Blue
    }

    story = []
    
    # ------------------ TITLE PAGE ------------------
    story.append(Spacer(1, 40))
    story.append(Paragraph("API Security Assessment Report", title_style))
    story.append(Paragraph(f"AI-Powered Automated Vulnerability Review", subtitle_style))
    
    # Metadata Block Table
    meta_data = [
        [Paragraph("<b>Target File:</b>", body_style), Paragraph(scan_meta.get("filename", "Unknown"), body_style)],
        [Paragraph("<b>Scan Status:</b>", body_style), Paragraph(scan_meta.get("status", "COMPLETED"), body_style)],
        [Paragraph("<b>Date Run:</b>", body_style), Paragraph(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), body_style)],
        [Paragraph("<b>Total Endpoints:</b>", body_style), Paragraph(str(scan_meta.get("total_endpoints", 0)), body_style)],
        [Paragraph("<b>Security Health Score:</b>", body_style), Paragraph(f"<b>{scan_meta.get('overall_score', 100.0)} / 100</b>", body_style)]
    ]
    t_meta = Table(meta_data, colWidths=[2.0 * inch, 4.0 * inch])
    t_meta.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 30))
    
    # Severity Count KPI Cards
    kpi_data = [
        [
            Paragraph("<font color='red'><b>CRITICAL</b></font><br/>" + str(scan_meta.get("critical_count", 0)), body_style),
            Paragraph("<font color='orange'><b>HIGH</b></font><br/>" + str(scan_meta.get("high_count", 0)), body_style),
            Paragraph("<font color='#F59E0B'><b>MEDIUM</b></font><br/>" + str(scan_meta.get("medium_count", 0)), body_style),
            Paragraph("<font color='blue'><b>LOW</b></font><br/>" + str(scan_meta.get("low_count", 0)), body_style)
        ]
    ]
    t_kpi = Table(kpi_data, colWidths=[1.5 * inch, 1.5 * inch, 1.5 * inch, 1.5 * inch])
    t_kpi.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F8FAFC")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#E2E8F0")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
        ('TOPPADDING', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
    ]))
    story.append(Paragraph("Findings Summary Matrix", h2_style))
    story.append(t_kpi)
    
    # Page break to findings
    story.append(PageBreak())
    
    # ------------------ DETAILED FINDINGS ------------------
    story.append(Paragraph("Detailed Security Findings", h1_style))
    story.append(Paragraph("The following list represents vulnerabilities identified by the API Review Rule Engine, mapped to OWASP categories, and explained using LLM context generation.", body_style))
    story.append(Spacer(1, 10))
    
    if not findings:
        story.append(Paragraph("<b>Excellent news! No security vulnerabilities were detected in this API specification scan.</b>", body_style))
    else:
        for idx, f in enumerate(findings, 1):
            finding_elements = []
            
            # Title header
            severity_label = f.get("severity", "MEDIUM").upper()
            title_text = f"#{idx}. {f.get('rule_name')} [{severity_label}]"
            finding_elements.append(Paragraph(title_text, h2_style))
            
            # Information sub-table
            info_data = [
                [Paragraph("<b>Endpoint Route:</b>", body_style), Paragraph(f"<code>{f.get('method')} {f.get('path')}</code>", body_style)],
                [Paragraph("<b>OWASP Mapping:</b>", body_style), Paragraph(f"<b>{f.get('owasp_category')}</b> - {f.get('owasp_title')}", body_style)],
                [Paragraph("<b>Risk Severity Score:</b>", body_style), Paragraph(f"{f.get('score')} / 100 (Severity: {f.get('severity')})", body_style)]
            ]
            t_info = Table(info_data, colWidths=[1.8 * inch, 4.2 * inch])
            t_info.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F8FAFC")),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
                ('LINEBELOW', (0,0), (-1,-1), 0.25, colors.HexColor("#CBD5E1")),
            ]))
            finding_elements.append(t_info)
            finding_elements.append(Spacer(1, 5))
            
            # Rule Description
            finding_elements.append(Paragraph(f"<b>Rule Description:</b> {f.get('description')}", body_style))
            
            # AI Explanation
            explanation_txt = f.get("explanation", "").replace("\n", "<br/>")
            finding_elements.append(Paragraph(f"<b>AI Explainer & Impact Analysis:</b> {explanation_txt}", body_style))
            
            # Code Mitigation
            mitigation_txt = f.get("mitigation", "")
            # Extract code snippet block if it has one
            if "```" in mitigation_txt:
                parts = mitigation_txt.split("```")
                # Assume odd indexes are code block snippets
                for p_idx, part in enumerate(parts):
                    if p_idx % 2 == 1:
                        # Clean language name if present
                        code_lines = part.split("\n")
                        if code_lines and code_lines[0].strip() in ["python", "javascript", "yaml", "json", "bash"]:
                            code_lines = code_lines[1:]
                        code_clean = "\n".join(code_lines).strip()
                        # HTML escape code
                        code_clean = code_clean.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                        finding_elements.append(Paragraph(code_clean.replace("\n", "<br/>").replace(" ", "&nbsp;"), code_style))
                    else:
                        text_clean = part.replace("\n", "<br/>")
                        finding_elements.append(Paragraph(f"<b>Mitigation Action Steps:</b> {text_clean}", body_style))
            else:
                mitigation_clean = mitigation_txt.replace("\n", "<br/>")
                finding_elements.append(Paragraph(f"<b>Mitigation Action Steps:</b> {mitigation_clean}", body_style))
                
            finding_elements.append(Spacer(1, 15))
            
            # Keep each vulnerability report together on a page to avoid awkward splits
            story.append(KeepTogether(finding_elements))
            
    # Build Document
    doc.build(story, canvasmaker=NumberedCanvas)
