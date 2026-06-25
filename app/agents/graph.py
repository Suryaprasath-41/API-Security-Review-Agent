import logging
from typing import Dict, Any, List, TypedDict
from langgraph.graph import StateGraph, END

# Import agents
from app.parsers.openapi_parser import OpenAPIParser
from app.agents.rule_agent import RuleEngineAgent
from app.agents.owasp_agent import OwaspAgent
from app.agents.llm_agent import LLMAgent
from app.agents.risk_agent import RiskAgent
from app.agents.report_agent import ReportAgent

# Import DB
from app.database import create_scan, update_scan, save_finding

logger = logging.getLogger(__name__)

class AgentState(TypedDict):
    file_path: str
    filename: str
    scan_id: int
    info: Dict[str, Any]
    servers: List[str]
    endpoints: List[Dict[str, Any]]
    security_schemes: Dict[str, Any]
    findings: List[Dict[str, Any]]
    overall_score: float
    summary: Dict[str, int]
    report_paths: Dict[str, str]

# Node 1: Parser Agent
def parser_node(state: AgentState) -> Dict[str, Any]:
    logger.info("Parser Agent: Extracting metadata and resolving references...")
    parser = OpenAPIParser(state["file_path"])
    info = parser.get_info()
    servers = parser.get_servers()
    security_schemes = parser.get_security_schemes()
    endpoints = parser.extract_endpoints()
    
    return {
        "info": info,
        "servers": servers,
        "security_schemes": security_schemes,
        "endpoints": endpoints
    }

# Node 2: Rule Engine Agent
def rule_engine_node(state: AgentState) -> Dict[str, Any]:
    logger.info("Rule Engine Agent: Executing 20 security rules...")
    engine = RuleEngineAgent()
    findings = engine.run_checks(
        endpoints=state["endpoints"],
        security_schemes=state["security_schemes"],
        servers=state["servers"]
    )
    return {"findings": findings}

# Node 3: OWASP Mapping Agent
def owasp_mapping_node(state: AgentState) -> Dict[str, Any]:
    logger.info("OWASP Mapping Agent: Classifying vulnerabilities...")
    agent = OwaspAgent()
    mapped = agent.map_findings(state["findings"])
    return {"findings": mapped}

# Node 4: LLM Explainer Agent
def llm_explain_node(state: AgentState) -> Dict[str, Any]:
    logger.info("LLM Explainer Agent: Analyzing risks and drafting mitigations...")
    agent = LLMAgent()
    findings = state["findings"]
    explained = []
    
    for f in findings:
        explanation_data = agent.explain_finding(
            rule_id=f["rule_id"],
            method=f["method"],
            path=f["path"]
        )
        f_copy = f.copy()
        f_copy["explanation"] = explanation_data["explanation"]
        f_copy["mitigation"] = f_copy.get("mitigation", "") + "\n\n**AI Implementation Guidance:**\n" + explanation_data["mitigation_snippet"]
        explained.append(f_copy)
        
    return {"findings": explained}

# Node 5: Risk Assessment Agent
def risk_assess_node(state: AgentState) -> Dict[str, Any]:
    logger.info("Risk Assessment Agent: Calculating risk scores and severity...")
    agent = RiskAgent()
    assessed = agent.assess_risk(state["findings"])
    
    # Calculate counts
    critical = 0
    high = 0
    medium = 0
    low = 0
    for f in assessed:
        sev = f["severity"].upper()
        if sev == "CRITICAL":
            critical += 1
        elif sev == "HIGH":
            high += 1
        elif sev == "MEDIUM":
            medium += 1
        elif sev == "LOW":
            low += 1
            
    summary = {
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "low_count": low
    }
    
    total_endpoints = len(state["endpoints"])
    health_score = agent.calculate_overall_health_score(assessed, total_endpoints)
    
    return {
        "findings": assessed,
        "overall_score": health_score,
        "summary": summary
    }

# Node 6: Reporting Agent
def reporting_node(state: AgentState) -> Dict[str, Any]:
    logger.info("Reporting Agent: Saving records and exporting reports...")
    scan_id = state["scan_id"]
    findings = state["findings"]
    summary = state["summary"]
    
    # Update findings in database
    for f in findings:
        save_finding(
            scan_id=scan_id,
            path=f["path"],
            method=f["method"],
            rule_id=f["rule_id"],
            rule_name=f["rule_name"],
            severity=f["severity"],
            description=f["description"],
            owasp_category=f.get("owasp_category"),
            owasp_title=f.get("owasp_title"),
            exploitability=f.get("exploitability", 3.0),
            exposure=f.get("exposure", 3.0),
            business_impact=f.get("business_impact", 3.0),
            score=f.get("score", 0.0),
            explanation=f.get("explanation", ""),
            mitigation=f.get("mitigation", "")
        )
        
    # Prepare metadata dict for reports
    scan_meta = {
        "filename": state["filename"],
        "status": "COMPLETED",
        "total_endpoints": len(state["endpoints"]),
        "overall_score": state["overall_score"],
        "critical_count": summary["critical_count"],
        "high_count": summary["high_count"],
        "medium_count": summary["medium_count"],
        "low_count": summary["low_count"]
    }
    
    # Update master scan record
    update_scan(
        scan_id=scan_id,
        status="COMPLETED",
        total_endpoints=scan_meta["total_endpoints"],
        critical_count=scan_meta["critical_count"],
        high_count=scan_meta["high_count"],
        medium_count=scan_meta["medium_count"],
        low_count=scan_meta["low_count"],
        overall_score=scan_meta["overall_score"]
    )
    
    # Generate files
    reporter = ReportAgent()
    paths = reporter.generate_reports(scan_id, scan_meta, findings)
    
    return {"report_paths": paths}

# Build State Graph
workflow = StateGraph(AgentState)

# Add Nodes
workflow.add_node("parser", parser_node)
workflow.add_node("rule_engine", rule_engine_node)
workflow.add_node("owasp_mapping", owasp_mapping_node)
workflow.add_node("llm_explain", llm_explain_node)
workflow.add_node("risk_assess", risk_assess_node)
workflow.add_node("reporting", reporting_node)

# Set entry point
workflow.set_entry_point("parser")

# Link Nodes sequentially
workflow.add_edge("parser", "rule_engine")
workflow.add_edge("rule_engine", "owasp_mapping")
workflow.add_edge("owasp_mapping", "llm_explain")
workflow.add_edge("llm_explain", "risk_assess")
workflow.add_edge("risk_assess", "reporting")
workflow.add_edge("reporting", END)

# Compile Graph
compiled_graph = workflow.compile()

def run_security_scan(file_path: str, filename: str, spec_id: int) -> int:
    """
    Triggers the LangGraph API review workflow.
    Returns the scan ID.
    """
    scan_id = create_scan(spec_id)
    
    # Initialize State
    initial_state: AgentState = {
        "file_path": file_path,
        "filename": filename,
        "scan_id": scan_id,
        "info": {},
        "servers": [],
        "endpoints": [],
        "security_schemes": {},
        "findings": [],
        "overall_score": 0.0,
        "summary": {},
        "report_paths": {}
    }
    
    try:
        compiled_graph.invoke(initial_state)
    except Exception as e:
        logger.exception(f"LangGraph execution failed for scan {scan_id}: {e}")
        # Update scan status to FAILED in case of exception
        update_scan(scan_id, "FAILED", 0, 0, 0, 0, 0, 0.0)
        raise e
        
    return scan_id
