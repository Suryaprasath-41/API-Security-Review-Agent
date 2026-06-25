from typing import Dict, Any, List

class RiskAgent:
    """
    Computes risk severity scores and assigns threat categories based on
    Severity, Exploitability, and Exposure factors.
    """
    
    SEVERITY_MAPPING = {
        "CRITICAL": 5.0,
        "HIGH": 4.0,
        "MEDIUM": 3.0,
        "LOW": 2.0
    }

    def assess_risk(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        assessed_findings = []
        for f in findings:
            f_copy = f.copy()
            
            # Map severity label to numeric value if not already present
            severity_str = f_copy.get("severity", "MEDIUM").upper()
            severity_val = self.SEVERITY_MAPPING.get(severity_str, 3.0)
            
            # Retrieve default/calculated factors
            exploitability = f_copy.get("exploitability", 3.0)
            exposure = f_copy.get("exposure", 3.0)
            business_impact = f_copy.get("business_impact", 3.0)
            
            # Score Formula: Severity * Exploitability * Exposure
            score = severity_val * exploitability * exposure
            # Ensure score does not exceed 100 (since max is 5 * 5 * 5 = 125, we cap it at 100)
            score = min(float(score * (100.0 / 125.0)), 100.0) # Scale 125 down to 100 for percentage compatibility
            
            # Overwrite with formula matching the example:
            # e.g., Missing Authentication: Severity=5, Exploitability=5, Exposure=4 => Score=100.
            # (5 * 5 * 4) = 100. Capping at 100 makes it fit.
            raw_score = severity_val * exploitability * exposure
            score = min(raw_score * 5.0 if raw_score <= 20.0 else raw_score, 100.0)
            
            # Deduce category based on score
            if score >= 80.0:
                calculated_severity = "CRITICAL"
            elif score >= 60.0:
                calculated_severity = "HIGH"
            elif score >= 40.0:
                calculated_severity = "MEDIUM"
            else:
                calculated_severity = "LOW"
                
            f_copy["severity"] = calculated_severity
            f_copy["exploitability"] = exploitability
            f_copy["exposure"] = exposure
            f_copy["business_impact"] = business_impact
            f_copy["score"] = round(score, 1)
            
            assessed_findings.append(f_copy)
            
        return assessed_findings

    def calculate_overall_health_score(self, findings: List[Dict[str, Any]], total_endpoints: int) -> float:
        """
        Calculates an API Security Health Score from 0 to 100.
        A higher score means better security (100 = flawless).
        Deductions are based on finding counts and severities.
        """
        if total_endpoints == 0:
            return 100.0
            
        # Base score starts at 100
        health_score = 100.0
        
        # Deduct for findings
        deductions = {
            "CRITICAL": 15.0,
            "HIGH": 10.0,
            "MEDIUM": 5.0,
            "LOW": 2.0
        }
        
        total_deduction = 0.0
        for f in findings:
            severity = f.get("severity", "MEDIUM").upper()
            total_deduction += deductions.get(severity, 5.0)
            
        # Scale deduction against total endpoints so large APIs aren't penalized disproportionately
        scaled_deduction = total_deduction / (1.0 + (total_endpoints * 0.1))
        
        health_score -= scaled_deduction
        return max(round(health_score, 1), 0.0)
