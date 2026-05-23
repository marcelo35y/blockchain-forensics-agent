import pytest

class TestReportGenerator:
    def test_agent_name(self, reporter):
        assert reporter.AGENT_NAME == "ReportGenerator"
    
    def test_generate_report(self, reporter):
        result = reporter.analyze({
            "investigations": [{"tx": "0x1"}],
            "findings": [{"type": "mixing", "severity": "high", "description": "Mixer detected"}],
            "risk_level": "high",
        })
        assert result["title"] == "Blockchain Forensic Investigation Report"
        assert result["risk_level"] == "high"
        assert len(result["recommendations"]) > 0
    
    def test_executive_summary(self, reporter):
        result = reporter.analyze({
            "investigations": [],
            "findings": [],
            "risk_level": "low",
        })
        assert "low" in result["executive_summary"].lower()
    
    def test_html_export(self, reporter):
        report = reporter.analyze({"investigations": [], "findings": [{"type": "test", "severity": "low", "description": "Test finding"}], "risk_level": "low"})
        html = reporter.export_html(report)
        assert "<html>" in html
        assert "Blockchain" in html
    
    def test_validate_input(self, reporter):
        assert reporter.validate_input("0x123") == True
