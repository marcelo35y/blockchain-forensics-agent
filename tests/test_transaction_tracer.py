import pytest

class TestTransactionTracer:
    def test_agent_name(self, tracer):
        assert tracer.AGENT_NAME == "TransactionTracer"
    
    def test_validate_valid_address(self, tracer):
        assert tracer.validate_input("0x1234567890abcdef1234567890abcdef12345678") == True
    
    def test_taint_set_and_get(self, tracer):
        tracker = tracer.taint_tracker
        tracker.set_taint("0xBAD", 0.9)
        tainted = tracker.get_tainted_addresses(0.1)
        addrs = [t["address"] if isinstance(t, dict) else t for t in tainted]
        assert any("0xBAD" in str(a) for a in addrs) or len(tainted) >= 1
    
    def test_agent_version(self, tracer):
        assert tracer.AGENT_VERSION == "1.0.0"
    
    def test_agent_not_running(self, tracer):
        assert tracer._is_running == False
    
    def test_agent_description(self, tracer):
        assert len(tracer.AGENT_DESCRIPTION) > 0
