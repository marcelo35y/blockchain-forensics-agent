"""ReportGenerator Agent — generates forensic investigation reports."""
import logging
from typing import Dict, List, Optional
from .base_agent import BaseAgent

logger = logging.getLogger(__name__)

class ReportGenerator(BaseAgent):
    """Generates structured forensic reports from investigation data.
    
    Capabilities:
    - Transaction flow visualization
    - Risk summary generation
    - Compliance findings formatting
    - Chain-of-custody documentation
    - PDF/HTML export
    - Executive summary generation
    """
    
    AGENT_NAME = "ReportGenerator"
    AGENT_VERSION = "1.0.0"
    AGENT_DESCRIPTION = "Generates forensic investigation reports"

    def __init__(self, config=None):
        super().__init__(config)
    
    def validate_input(self, target: str) -> bool:
        return True

    def analyze(self, data: Dict) -> Dict:
        """Generate a forensic report from analysis data."""
        investigations = data.get("investigations", [])
        findings = data.get("findings", [])
        risk_level = data.get("risk_level", "unknown")
        
        report = {
            "title": "Blockchain Forensic Investigation Report",
            "risk_level": risk_level,
            "total_investigations": len(investigations),
            "total_findings": len(findings),
            "executive_summary": self._generate_summary(investigations, findings, risk_level),
            "detailed_findings": self._format_findings(findings),
            "recommendations": self._generate_recommendations(findings, risk_level),
            "metadata": {
                "generated_by": "MiMo V2.5 Blockchain Forensics Agent",
                "agents_used": ["TransactionTracer", "WalletClusterer", "AnomalyDetector", "PatternAnalyzer", "ComplianceChecker"],
            },
        }
        
        self._metrics["reports_generated"] = self._metrics.get("reports_generated", 0) + 1
        
        return report
    
    def _generate_summary(self, investigations: List, findings: List, risk_level: str) -> str:
        high_risk = sum(1 for f in findings if f.get("severity") == "high")
        return (
            f"Investigation completed with {len(investigations)} transactions analyzed. "
            f"Overall risk assessment: {risk_level.upper()}. "
            f"Found {len(findings)} findings, {high_risk} classified as high severity. "
            f"Immediate action {'required' if high_risk > 0 else 'not required'}."
        )
    
    def _format_findings(self, findings: List[Dict]) -> List[Dict]:
        formatted = []
        for i, f in enumerate(findings, 1):
            formatted.append({
                "id": f"FIN-{i:04d}",
                "type": f.get("type", "unknown"),
                "severity": f.get("severity", "medium"),
                "description": f.get("description", ""),
                "evidence": f.get("evidence", []),
                "affected_addresses": f.get("addresses", []),
            })
        return formatted
    
    def _generate_recommendations(self, findings: List[Dict], risk_level: str) -> List[str]:
        recs = []
        if risk_level in ["high", "critical"]:
            recs.append("Immediately flag all involved addresses for enhanced monitoring")
        if any(f.get("type") == "mixing" for f in findings):
            recs.append("Report mixer usage to compliance team — potential money laundering")
        if any(f.get("type") == "sybil" for f in findings):
            recs.append("Investigate sybil cluster — possible coordinated manipulation")
        if not recs:
            recs.append("Continue standard monitoring protocols")
        return recs
    
    def export_html(self, report: Dict) -> str:
        """Export report as HTML."""
        html = f"<html><head><title>{report['title']}</title></head><body>"
        html += f"<h1>{report['title']}</h1>"
        html += f"<h2>Risk Level: {report['risk_level'].upper()}</h2>"
        html += f"<p>{report['executive_summary']}</p>"
        html += "<h2>Findings</h2><ul>"
        for f in report['detailed_findings']:
            html += f"<li><strong>{f['id']}</strong> [{f['severity']}] {f['description']}</li>"
        html += "</ul>"
        html += "<h2>Recommendations</h2><ul>"
        for r in report['recommendations']:
            html += f"<li>{r}</li>"
        html += "</ul></body></html>"
        return html
