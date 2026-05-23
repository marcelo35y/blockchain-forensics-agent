import pytest

class TestWalletClusterer:
    def test_agent_name(self, clusterer):
        assert clusterer.AGENT_NAME == "WalletClusterer"
    
    def test_validate_input(self, clusterer):
        assert clusterer.validate_input("0x1234567890abcdef1234567890abcdef12345678") == True
    
    def test_co_spending_analyzer(self):
        from src.agents.wallet_clusterer import CoSpendingAnalyzer
        analyzer = CoSpendingAnalyzer()
        assert analyzer is not None
    
    def test_behavioral_analyzer(self):
        from src.agents.wallet_clusterer import BehavioralAnalyzer
        analyzer = BehavioralAnalyzer()
        assert analyzer is not None
    
    def test_temporal_analyzer(self):
        from src.agents.wallet_clusterer import TemporalAnalyzer
        analyzer = TemporalAnalyzer()
        assert analyzer is not None
