import pytest
from pathlib import Path
from app.parsers.openapi_parser import OpenAPIParser
from app.agents.rule_agent import RuleEngineAgent
from app.agents.owasp_agent import OwaspAgent
from app.agents.risk_agent import RiskAgent

@pytest.fixture
def vulnerable_spec_path():
    return Path(__file__).resolve().parent / "sample_vulnerable_openapi.yaml"

def test_parser_loads_metadata(vulnerable_spec_path):
    parser = OpenAPIParser(str(vulnerable_spec_path))
    info = parser.get_info()
    servers = parser.get_servers()
    
    assert info["title"] == "Vulnerable E-Commerce API"
    assert "http://api.vulnerableapp.local/v1" in servers

def test_parser_extracts_endpoints(vulnerable_spec_path):
    parser = OpenAPIParser(str(vulnerable_spec_path))
    endpoints = parser.extract_endpoints()
    
    paths = [ep["path"] for ep in endpoints]
    assert "/users" in paths
    assert "/users/{id}" in paths
    assert "/admin/deleteUser/{id}" in paths
    assert "/search" in paths
    assert "/users/avatar" in paths

def test_rule_engine_detects_flaws(vulnerable_spec_path):
    parser = OpenAPIParser(str(vulnerable_spec_path))
    endpoints = parser.extract_endpoints()
    security_schemes = parser.get_security_schemes()
    servers = parser.get_servers()
    
    engine = RuleEngineAgent()
    findings = engine.run_checks(endpoints, security_schemes, servers)
    
    rule_ids = [f["rule_id"] for f in findings]
    
    # 1. Plaintext HTTP protocol
    assert "RULE_WEAK_PROTOCOL" in rule_ids
    
    # 2. Unprotected endpoints
    assert "RULE_MISSING_AUTH" in rule_ids
    
    # 3. Public admin delete
    assert "RULE_UNRESTRICTED_DELETE" in rule_ids
    
    # 4. Sensitive parameter in URL query
    assert "RULE_SENSITIVE_QUERY_PARAMS" in rule_ids
    
    # 5. IDOR path variable
    assert "RULE_INSECURE_IDOR_RISK" in rule_ids
    
    # 6. SQL Injection risk on query string
    assert "RULE_SQL_INJECTION_RISK" in rule_ids
    
    # 7. Unrestricted file upload
    assert "RULE_DANGEROUS_FILE_UPLOAD" in rule_ids

def test_owasp_mapping(vulnerable_spec_path):
    parser = OpenAPIParser(str(vulnerable_spec_path))
    endpoints = parser.extract_endpoints()
    security_schemes = parser.get_security_schemes()
    servers = parser.get_servers()
    
    engine = RuleEngineAgent()
    findings = engine.run_checks(endpoints, security_schemes, servers)
    
    owasp = OwaspAgent()
    mapped_findings = owasp.map_findings(findings)
    
    for f in mapped_findings:
        assert "owasp_category" in f
        assert "owasp_title" in f
        
    # Spot check BOLA mapping
    bola_findings = [f for f in mapped_findings if f["rule_id"] == "RULE_INSECURE_IDOR_RISK"]
    assert len(bola_findings) > 0
    assert bola_findings[0]["owasp_category"] == "API1:2023"

def test_risk_scoring(vulnerable_spec_path):
    parser = OpenAPIParser(str(vulnerable_spec_path))
    endpoints = parser.extract_endpoints()
    security_schemes = parser.get_security_schemes()
    servers = parser.get_servers()
    
    engine = RuleEngineAgent()
    findings = engine.run_checks(endpoints, security_schemes, servers)
    
    risk = RiskAgent()
    assessed_findings = risk.assess_risk(findings)
    
    for f in assessed_findings:
        assert "score" in f
        assert f["score"] >= 0.0 and f["score"] <= 100.0
        
    # Check overall health calculation
    health_score = risk.calculate_overall_health_score(assessed_findings, len(endpoints))
    assert health_score >= 0.0 and health_score <= 100.0
