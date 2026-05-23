import pytest

class TestModels:
    def test_severity_levels(self):
        from src.models.analysis import SeverityLevel
        assert SeverityLevel.CRITICAL.value == "critical"
        assert SeverityLevel.HIGH.value == "high"
    
    def test_risk_categories(self):
        from src.models.analysis import RiskCategory
        assert RiskCategory.MONEY_LAUNDERING.value == "money_laundering"
        assert RiskCategory.SCAM.value == "scam"
    
    def test_risk_score(self):
        from src.models.analysis import RiskScore
        score = RiskScore(overall=0.75, confidence=0.9)
        assert score.overall == 0.75
        score.add_factor("test", 0.5, 0.3, "test factor")
        assert len(score.factors) == 1
    
    def test_analysis_result(self):
        from src.models.analysis import AnalysisResult
        result = AnalysisResult(analysis_id="test-001", target="0x123")
        assert result.analysis_id == "test-001"
        assert result.target == "0x123"
    
    def test_transaction_model(self):
        from src.models.transaction import Transaction
        assert Transaction is not None
    
    def test_wallet_model(self):
        from src.models.wallet import Wallet
        assert Wallet is not None
