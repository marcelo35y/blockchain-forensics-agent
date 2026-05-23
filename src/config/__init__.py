"""
Configuration management for Blockchain Forensics Agent.
Centralized configuration for all agents, blockchain adapters, and analysis parameters.
"""

import os
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path


@dataclass
class BlockchainConfig:
    """Configuration for blockchain network connections."""
    network: str = "bitcoin"
    rpc_url: str = ""
    api_key: str = ""
    explorer_url: str = ""
    confirmations_required: int = 6
    max_trace_depth: int = 10
    rate_limit_per_second: float = 5.0
    timeout_seconds: int = 30
    cache_ttl_seconds: int = 300

    def validate(self) -> bool:
        """Validate blockchain configuration."""
        valid_networks = ["bitcoin", "ethereum", "litecoin", "dash", "monero", "zcash"]
        if self.network not in valid_networks:
            raise ValueError(f"Unsupported network: {self.network}. Valid: {valid_networks}")
        if self.max_trace_depth < 1 or self.max_trace_depth > 50:
            raise ValueError("max_trace_depth must be between 1 and 50")
        if self.confirmations_required < 0:
            raise ValueError("confirmations_required must be non-negative")
        return True


@dataclass
class AnomalyConfig:
    """Configuration for anomaly detection parameters."""
    zscore_threshold: float = 3.0
    iqr_multiplier: float = 1.5
    min_cluster_size: int = 3
    temporal_window_hours: int = 24
    velocity_threshold: float = 0.8
    amount_percentile_threshold: float = 95.0
    enable_ml_detection: bool = True
    contamination_factor: float = 0.05
    feature_weights: Dict[str, float] = field(default_factory=lambda: {
        "amount": 0.3,
        "frequency": 0.25,
        "temporal": 0.2,
        "counterparty_diversity": 0.15,
        "address_age": 0.1,
    })


@dataclass
class ComplianceConfig:
    """Configuration for compliance checking rules."""
    jurisdictions: List[str] = field(default_factory=lambda: ["US", "EU", "UK"])
    fatf_travel_rule_threshold: float = 1000.0
    structuring_threshold: float = 10000.0
    high_risk_countries: List[str] = field(default_factory=lambda: [
        "KP", "IR", "SY", "CU", "VE", "MM", "BY", "RU", "CN"
    ])
    sanctions_list_url: str = "https://api.example.com/sanctions"
    pep_screening_enabled: bool = True
    adverse_media_enabled: bool = True
    max_risk_score: float = 100.0
    aml_reporting_threshold: float = 15000.0
    suspicious_activity_thresholds: Dict[str, float] = field(default_factory=lambda: {
        "rapid_movement": 50000.0,
        "structuring": 10000.0,
        "unusual_volume": 100000.0,
        "dormant_activation": 25000.0,
    })


@dataclass
class ClusteringConfig:
    """Configuration for wallet clustering analysis."""
    co_spending_weight: float = 0.35
    temporal_weight: float = 0.25
    behavioral_weight: float = 0.20
    address_reuse_weight: float = 0.10
    graph_weight: float = 0.10
    min_similarity_score: float = 0.5
    max_cluster_depth: int = 5
    enable_heuristic_analysis: bool = True
    consolidation_threshold: float = 0.7
    merge_confidence_threshold: float = 0.8


@dataclass
class PatternConfig:
    """Configuration for suspicious pattern detection."""
    mixing_indicators: Dict[str, float] = field(default_factory=lambda: {
        "equal_output_values": 0.7,
        "multiple_inputs_outputs": 0.6,
        "round_amounts": 0.3,
        "temporal_clustering": 0.5,
        "peel_chain_pattern": 0.8,
    })
    layering_hops: int = 5
    layering_threshold: float = 0.6
    structuring_detection_window: int = 24
    structuring_count_threshold: int = 5
    round_trip_time_window: int = 48
    min_pattern_confidence: float = 0.5
    enable_peel_chain_detection: bool = True
    peel_chain_min_length: int = 3


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    output_dir: str = "reports"
    formats: List[str] = field(default_factory=lambda: ["json", "html", "markdown", "pdf"])
    include_charts: bool = True
    include_raw_data: bool = False
    include_confidence_scores: bool = True
    template_dir: str = "templates"
    max_findings_per_report: int = 100
    severity_levels: List[str] = field(default_factory=lambda: [
        "critical", "high", "medium", "low", "info"
    ])
    executive_summary: bool = True
    detailed_analysis: bool = True
    recommendations: bool = True


@dataclass
class AgentConfig:
    """Master configuration for all agents."""
    blockchain: BlockchainConfig = field(default_factory=BlockchainConfig)
    anomaly: AnomalyConfig = field(default_factory=AnomalyConfig)
    compliance: ComplianceConfig = field(default_factory=ComplianceConfig)
    clustering: ClusteringConfig = field(default_factory=ClusteringConfig)
    patterns: PatternConfig = field(default_factory=PatternConfig)
    report: ReportConfig = field(default_factory=ReportConfig)

    log_level: str = "INFO"
    debug: bool = False
    parallel_processing: bool = True
    max_workers: int = 4
    data_retention_days: int = 90

    @classmethod
    def from_env(cls) -> "AgentConfig":
        """Create configuration from environment variables."""
        config = cls()
        config.blockchain.network = os.getenv("BCFA_NETWORK", config.blockchain.network)
        config.blockchain.rpc_url = os.getenv("BCFA_RPC_URL", config.blockchain.rpc_url)
        config.blockchain.api_key = os.getenv("BCFA_API_KEY", config.blockchain.api_key)
        config.log_level = os.getenv("BCFA_LOG_LEVEL", config.log_level)
        config.debug = os.getenv("BCFA_DEBUG", "false").lower() == "true"
        config.max_workers = int(os.getenv("BCFA_MAX_WORKERS", str(config.max_workers)))
        return config

    @classmethod
    def from_file(cls, filepath: str) -> "AgentConfig":
        """Load configuration from JSON file."""
        with open(filepath, "r") as f:
            data = json.load(f)
        config = cls()
        if "blockchain" in data:
            for k, v in data["blockchain"].items():
                if hasattr(config.blockchain, k):
                    setattr(config.blockchain, k, v)
        if "anomaly" in data:
            for k, v in data["anomaly"].items():
                if hasattr(config.anomaly, k):
                    setattr(config.anomaly, k, v)
        if "compliance" in data:
            for k, v in data["compliance"].items():
                if hasattr(config.compliance, k):
                    setattr(config.compliance, k, v)
        if "clustering" in data:
            for k, v in data["clustering"].items():
                if hasattr(config.clustering, k):
                    setattr(config.clustering, k, v)
        if "patterns" in data:
            for k, v in data["patterns"].items():
                if hasattr(config.patterns, k):
                    setattr(config.patterns, k, v)
        if "report" in data:
            for k, v in data["report"].items():
                if hasattr(config.report, k):
                    setattr(config.report, k, v)
        for key in ["log_level", "debug", "parallel_processing", "max_workers", "data_retention_days"]:
            if key in data:
                setattr(config, key, data[key])
        return config

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        def _dc_to_dict(obj):
            if hasattr(obj, "__dataclass_fields__"):
                return {k: _dc_to_dict(v) for k, v in obj.__dict__.items()}
            return obj
        return _dc_to_dict(self)

    def save(self, filepath: str) -> None:
        """Save configuration to JSON file."""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(self.to_dict(), f, indent=2)


DEFAULT_CONFIG = AgentConfig()
