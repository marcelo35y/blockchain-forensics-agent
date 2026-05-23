import pytest, sys
sys.path.insert(0, ".")
from src.agents import (
    TransactionTracer, WalletClusterer,
    AnomalyDetector, PatternAnalyzer, ComplianceChecker, ReportGenerator
)
from src.config import AgentConfig

@pytest.fixture
def config():
    return AgentConfig()

@pytest.fixture
def tracer(config):
    return TransactionTracer(config)

@pytest.fixture
def clusterer(config):
    return WalletClusterer(config)

@pytest.fixture
def anomaly(config):
    return AnomalyDetector(config)

@pytest.fixture
def pattern(config):
    return PatternAnalyzer(config)

@pytest.fixture
def compliance(config):
    return ComplianceChecker(config)

@pytest.fixture
def reporter(config):
    return ReportGenerator(config)

SAMPLE_ADDR = "0x1234567890abcdef1234567890abcdef12345678"
