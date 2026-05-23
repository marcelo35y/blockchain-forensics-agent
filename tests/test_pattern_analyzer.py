import pytest

class TestPatternAnalyzer:
    def test_agent_name(self, pattern):
        assert pattern.AGENT_NAME == "PatternAnalyzer"
    
    def test_mixing_detector(self):
        from src.agents.pattern_analyzer import MixingDetector
        det = MixingDetector()
        assert det is not None
    
    def test_layering_detector(self):
        from src.agents.pattern_analyzer import LayeringDetector
        det = LayeringDetector()
        assert det is not None
    
    def test_peel_chain_detector(self):
        from src.agents.pattern_analyzer import PeelChainDetector
        det = PeelChainDetector()
        assert det is not None
    
    def test_round_trip_detector(self):
        from src.agents.pattern_analyzer import RoundTripDetector
        det = RoundTripDetector()
        assert det is not None
    
    def test_validate_input(self, pattern):
        assert pattern.validate_input("0x1234567890abcdef1234567890abcdef12345678") == True
