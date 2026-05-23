import pytest

class TestComplianceChecker:
    def test_agent_name(self, compliance):
        assert compliance.AGENT_NAME == "ComplianceChecker"
    
    def test_sanctions_screener(self):
        from src.agents.compliance_checker import SanctionsScreener
        screener = SanctionsScreener()
        screener.add_sanctioned_address("0xBAD", "BadActor")
        result = screener.screen_address("0xBAD")
        assert result["is_sanctioned"] == True
        assert result["entity"] == "BadActor"
    
    def test_clean_address_screening(self):
        from src.agents.compliance_checker import SanctionsScreener
        screener = SanctionsScreener()
        result = screener.screen_address("0x1234567890abcdef1234567890abcdef12345678")
        assert result["is_sanctioned"] == False
    
    def test_structuring_detector(self):
        from src.agents.compliance_checker import StructuringDetector
        det = StructuringDetector()
        assert det is not None
    
    def test_fatf_travel_rule(self):
        from src.agents.compliance_checker import FATFTravelRuleChecker
        checker = FATFTravelRuleChecker()
        assert checker is not None
    
    def test_validate_input(self, compliance):
        assert compliance.validate_input("0x1234567890abcdef1234567890abcdef12345678") == True
