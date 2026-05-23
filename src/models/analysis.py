"""
Analysis result data models for blockchain forensics.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum


class SeverityLevel(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskCategory(Enum):
    """Categories of risk in blockchain analysis."""
    MONEY_LAUNDERING = "money_laundering"
    FRAUD = "fraud"
    RANSOMWARE = "ransomware"
    DARKNET = "darknet"
    SANCTIONS_EVASION = "sanctions_evasion"
    TERRORISM_FINANCING = "terrorism_financing"
    TAX_EVASION = "tax_evasion"
    SCAM = "scam"
    THEFT = "theft"
    MIXER_USAGE = "mixer_usage"
    STRUCTURING = "structuring"
    UNUSUAL_ACTIVITY = "unusual_activity"
    UNKNOWN = "unknown"


@dataclass
class RiskScore:
    """Composite risk score with category breakdowns."""
    overall: float = 0.0
    categories: Dict[str, float] = field(default_factory=dict)
    confidence: float = 0.0
    factors: List[Dict[str, Any]] = field(default_factory=list)

    def add_factor(self, name: str, score: float, weight: float, description: str) -> None:
        self.factors.append({
            "name": name,
            "score": score,
            "weight": weight,
            "weighted_score": score * weight,
            "description": description,
        })
        self._recalculate()

    def _recalculate(self) -> None:
        if self.factors:
            total_weight = sum(f["weight"] for f in self.factors)
            if total_weight > 0:
                self.overall = sum(f["weighted_score"] for f in self.factors) / total_weight

    @property
    def severity(self) -> SeverityLevel:
        if self.overall >= 80:
            return SeverityLevel.CRITICAL
        elif self.overall >= 60:
            return SeverityLevel.HIGH
        elif self.overall >= 40:
            return SeverityLevel.MEDIUM
        elif self.overall >= 20:
            return SeverityLevel.LOW
        return SeverityLevel.INFO

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall": self.overall,
            "severity": self.severity.value,
            "categories": self.categories,
            "confidence": self.confidence,
            "factors": self.factors,
        }


@dataclass
class Finding:
    """Individual forensic finding."""
    finding_id: str
    title: str
    description: str
    severity: SeverityLevel = SeverityLevel.INFO
    category: RiskCategory = RiskCategory.UNKNOWN
    confidence: float = 0.0
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    affected_addresses: List[str] = field(default_factory=list)
    affected_transactions: List[str] = field(default_factory=list)
    recommendation: str = ""
    source_agent: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_evidence(self, evidence_type: str, description: str, data: Any = None) -> None:
        self.evidence.append({
            "type": evidence_type,
            "description": description,
            "data": data,
            "timestamp": datetime.utcnow().isoformat(),
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "confidence": self.confidence,
            "evidence_count": len(self.evidence),
            "affected_addresses": self.affected_addresses,
            "affected_transactions": self.affected_transactions,
            "recommendation": self.recommendation,
            "source_agent": self.source_agent,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class PatternMatch:
    """Result of pattern detection."""
    pattern_id: str
    pattern_type: str
    pattern_name: str
    description: str
    confidence: float = 0.0
    risk_level: SeverityLevel = SeverityLevel.INFO
    transactions: List[str] = field(default_factory=list)
    addresses: List[str] = field(default_factory=list)
    amount_involved: float = 0.0
    time_span_hours: float = 0.0
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "pattern_type": self.pattern_type,
            "pattern_name": self.pattern_name,
            "description": self.description,
            "confidence": self.confidence,
            "risk_level": self.risk_level.value,
            "transaction_count": len(self.transactions),
            "address_count": len(self.addresses),
            "amount_involved": self.amount_involved,
            "time_span_hours": self.time_span_hours,
            "indicators": self.indicators,
        }


@dataclass
class ComplianceResult:
    """Result of compliance checking."""
    result_id: str
    entity: str
    jurisdiction: str = ""
    is_compliant: bool = True
    violations: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[Dict[str, Any]] = field(default_factory=list)
    risk_rating: SeverityLevel = SeverityLevel.INFO
    sanctions_match: bool = False
    pep_match: bool = False
    adverse_media: bool = False
    recommended_actions: List[str] = field(default_factory=list)
    reporting_required: bool = False
    reporting_jurisdiction: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def add_violation(self, rule: str, description: str, severity: SeverityLevel) -> None:
        self.violations.append({
            "rule": rule,
            "description": description,
            "severity": severity.value,
            "timestamp": datetime.utcnow().isoformat(),
        })
        self.is_compliant = False
        if severity.value in ["critical", "high"]:
            self.risk_rating = severity

    def add_warning(self, rule: str, description: str) -> None:
        self.warnings.append({
            "rule": rule,
            "description": description,
            "timestamp": datetime.utcnow().isoformat(),
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result_id": self.result_id,
            "entity": self.entity,
            "jurisdiction": self.jurisdiction,
            "is_compliant": self.is_compliant,
            "violations": self.violations,
            "warnings": self.warnings,
            "risk_rating": self.risk_rating.value,
            "sanctions_match": self.sanctions_match,
            "pep_match": self.pep_match,
            "reporting_required": self.reporting_required,
            "recommended_actions": self.recommended_actions,
        }


@dataclass
class TracingResult:
    """Result of fund tracing analysis."""
    trace_id: str
    source_address: str
    network: str = "bitcoin"
    max_depth_reached: int = 0
    total_addresses: int = 0
    total_value_traced: float = 0.0
    paths: List[List[Dict[str, Any]]] = field(default_factory=list)
    endpoints: List[Dict[str, Any]] = field(default_factory=list)
    high_risk_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    taint_analysis: Dict[str, float] = field(default_factory=dict)
    flow_graph: Dict[str, Any] = field(default_factory=dict)
    analysis_time_seconds: float = 0.0

    def add_path(self, path: List[Dict[str, Any]]) -> None:
        self.paths.append(path)
        if path:
            endpoint = path[-1]
            self.endpoints.append(endpoint)
            if endpoint.get("risk_score", 0) > 0.7:
                self.high_risk_endpoints.append(endpoint)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "source_address": self.source_address,
            "network": self.network,
            "max_depth_reached": self.max_depth_reached,
            "total_addresses": self.total_addresses,
            "total_value_traced": self.total_value_traced,
            "path_count": len(self.paths),
            "endpoint_count": len(self.endpoints),
            "high_risk_endpoint_count": len(self.high_risk_endpoints),
            "taint_analysis": self.taint_analysis,
            "analysis_time_seconds": self.analysis_time_seconds,
        }


@dataclass
class AnalysisResult:
    """
    Comprehensive analysis result combining all agent outputs.
    The main container for all forensic analysis findings.
    """
    analysis_id: str
    target: str  # address, transaction, or entity being analyzed
    analysis_type: str = "full"  # full, transaction, address, cluster
    network: str = "bitcoin"
    timestamp: datetime = field(default_factory=datetime.utcnow)
    risk_score: RiskScore = field(default_factory=RiskScore)
    findings: List[Finding] = field(default_factory=list)
    patterns: List[PatternMatch] = field(default_factory=list)
    compliance_results: List[ComplianceResult] = field(default_factory=list)
    tracing_results: List[TracingResult] = field(default_factory=list)
    agent_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    execution_time_seconds: float = 0.0
    status: str = "pending"
    error: Optional[str] = None

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_pattern(self, pattern: PatternMatch) -> None:
        self.patterns.append(pattern)

    @property
    def critical_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == SeverityLevel.CRITICAL]

    @property
    def high_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == SeverityLevel.HIGH]

    @property
    def findings_summary(self) -> Dict[str, int]:
        summary = {level.value: 0 for level in SeverityLevel}
        for f in self.findings:
            summary[f.severity.value] += 1
        return summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "target": self.target,
            "analysis_type": self.analysis_type,
            "network": self.network,
            "timestamp": self.timestamp.isoformat(),
            "risk_score": self.risk_score.to_dict(),
            "findings_count": len(self.findings),
            "findings_summary": self.findings_summary,
            "patterns_count": len(self.patterns),
            "compliance_results_count": len(self.compliance_results),
            "tracing_results_count": len(self.tracing_results),
            "agent_results": self.agent_results,
            "execution_time_seconds": self.execution_time_seconds,
            "status": self.status,
            "error": self.error,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)
