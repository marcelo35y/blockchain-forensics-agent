"""
ComplianceChecker Agent — AML/CFT compliance checking.

Implements compliance checks for:
- OFAC sanctions screening
- FATF Travel Rule compliance
- Anti-Money Laundering (AML) detection
- Counter Financing of Terrorism (CFT) checks
- Structuring detection (breaking up transactions to avoid reporting)
- Suspicious Activity Report (SAR) assessment
- Know Your Customer (KYC) risk assessment
"""

import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from collections import defaultdict

from src.agents.base_agent import BaseAgent
from src.models.transaction import Transaction
from src.models.wallet import Wallet, WalletType, AddressType
from src.models.analysis import (
    AnalysisResult, Finding, ComplianceResult, RiskScore,
    SeverityLevel, RiskCategory,
)
from src.utils.blockchain_adapter import MockBlockchainAdapter, BlockchainAdapter
from src.config import AgentConfig


logger = logging.getLogger(__name__)


# Known sanctioned addresses (example data for demonstration)
SANCTIONED_ADDRESSES = {
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa": "Genesis Block Address",
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh": "Example Sanctioned Entity",
}

# Known exchange addresses (example data)
KNOWN_EXCHANGES = {
    "1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s": "Binance",
    "3Kzh9qAqVWQhEsfQz7zEQL1EuSx5tyNLNS": "Coinbase",
}

# Known mixer addresses (example data)
KNOWN_MIXERS = {
    "bc1qa5wkgaew2dkv56kc6hp23ly7fz289203x4n4n6": "Tornado Cash",
}

# High-risk jurisdiction country codes
HIGH_RISK_COUNTRIES = {"KP", "IR", "SY", "CU", "VE", "MM", "BY", "RU"}


class SanctionsScreener:
    """Screen addresses against sanctions lists."""

    def __init__(self):
        self.sanctioned_addresses: Dict[str, str] = dict(SANCTIONED_ADDRESSES)
        self.sanctioned_entities: Dict[str, List[str]] = {}

    def add_sanctioned_address(self, address: str, entity: str) -> None:
        self.sanctioned_addresses[address] = entity

    def screen_address(self, address: str) -> Dict[str, Any]:
        """Screen a single address against sanctions lists."""
        if address in self.sanctioned_addresses:
            return {
                "is_sanctioned": True,
                "entity": self.sanctioned_addresses[address],
                "list": "OFAC_SDN",
                "match_type": "exact",
            }
        return {"is_sanctioned": False}

    def screen_transaction(self, tx: Transaction) -> Dict[str, Any]:
        """Screen all addresses in a transaction."""
        results = {
            "sanctioned_inputs": [],
            "sanctioned_outputs": [],
            "has_sanctioned": False,
        }

        for inp in tx.inputs:
            screen = self.screen_address(inp.address)
            if screen["is_sanctioned"]:
                results["sanctioned_inputs"].append({
                    "address": inp.address,
                    "entity": screen["entity"],
                    "value": inp.value,
                })

        for out in tx.outputs:
            screen = self.screen_address(out.address)
            if screen["is_sanctioned"]:
                results["sanctioned_outputs"].append({
                    "address": out.address,
                    "entity": screen["entity"],
                    "value": out.value,
                })

        results["has_sanctioned"] = bool(
            results["sanctioned_inputs"] or results["sanctioned_outputs"]
        )
        return results


class StructuringDetector:
    """Detect transaction structuring (breaking up transactions to avoid thresholds)."""

    def __init__(self, threshold: float = 10000.0, window_hours: int = 24,
                 min_transactions: int = 3):
        self.threshold = threshold
        self.window_hours = window_hours
        self.min_transactions = min_transactions

    def detect_structuring(self, transactions: List[Transaction],
                           address: str) -> List[Dict[str, Any]]:
        """
        Detect structuring patterns where multiple transactions
        just below the threshold are made within a time window.
        """
        # Filter transactions involving the address
        relevant_txs = []
        for tx in transactions:
            for out in tx.outputs:
                if out.address == address:
                    relevant_txs.append((tx, out.value, "receive"))
            for inp in tx.inputs:
                if inp.address == address:
                    relevant_txs.append((tx, inp.value, "send"))

        # Sort by timestamp
        relevant_txs.sort(key=lambda x: x[0].timestamp)

        violations = []
        window_delta = timedelta(hours=self.window_hours)
        window_txs: List[tuple] = []

        for tx, value, direction in relevant_txs:
            # Clean old transactions from window
            window_txs = [
                (t, v, d) for t, v, d in window_txs
                if tx.timestamp - t.timestamp <= window_delta
            ]

            if value < self.threshold and value > self.threshold * 0.5:
                window_txs.append((tx, value, direction))

                # Check if window has enough transactions
                if len(window_txs) >= self.min_transactions:
                    total = sum(v for _, v, _ in window_txs)
                    if total >= self.threshold:
                        violations.append({
                            "type": "structuring",
                            "transaction_count": len(window_txs),
                            "total_value": total,
                            "threshold": self.threshold,
                            "individual_values": [v for _, v, _ in window_txs],
                            "time_span_hours": (
                                window_txs[-1][0].timestamp - window_txs[0][0].timestamp
                            ).total_seconds() / 3600,
                            "direction": window_txs[0][2],
                        })

        return violations


class FATFTravelRuleChecker:
    """Check compliance with FATF Travel Rule requirements."""

    def __init__(self, threshold: float = 1000.0):
        self.threshold = threshold

    def check_compliance(self, transactions: List[Transaction],
                         address: str) -> List[Dict[str, Any]]:
        """
        Check if transactions comply with FATF Travel Rule.
        Transactions above threshold require originator/beneficiary information.
        """
        violations = []

        for tx in transactions:
            relevant_value = 0.0
            role = ""

            for out in tx.outputs:
                if out.address == address:
                    relevant_value += out.value
                    role = "beneficiary"

            for inp in tx.inputs:
                if inp.address == address:
                    relevant_value += inp.value
                    role = "originator"

            if relevant_value >= self.threshold:
                # In a real system, check if originator/beneficiary info is available
                # For demo, we flag high-value transactions
                violations.append({
                    "tx_hash": tx.tx_hash,
                    "value": relevant_value,
                    "threshold": self.threshold,
                    "role": role,
                    "requirement": "originator_beneficiary_info",
                    "status": "requires_verification",
                })

        return violations


class ComplianceChecker(BaseAgent):
    """
    Agent for AML/CFT compliance checking.
    Screens addresses and transactions against regulatory requirements.
    """

    AGENT_NAME = "ComplianceChecker"
    AGENT_VERSION = "1.0.0"
    AGENT_DESCRIPTION = "AML/CFT compliance with OFAC, FATF Travel Rule, and sanctions screening"

    def __init__(self, config: Optional[AgentConfig] = None, adapter: Optional[BlockchainAdapter] = None):
        super().__init__(config)
        self.adapter = adapter or MockBlockchainAdapter(
            network=self.config.blockchain.network
        )
        self.sanctions_screener = SanctionsScreener()
        self.structuring_detector = StructuringDetector(
            threshold=self.config.compliance.structuring_threshold,
        )
        self.travel_rule_checker = FATFTravelRuleChecker(
            threshold=self.config.compliance.fatf_travel_rule_threshold,
        )

    def validate_input(self, target: str) -> bool:
        """Validate target is a valid address."""
        return bool(target and len(target) >= 10)

    def analyze(self, target: str, context: Dict[str, Any] = None) -> AnalysisResult:
        """Perform comprehensive compliance analysis."""
        context = context or {}
        result = AnalysisResult(
            analysis_id=f"compliance_{uuid.uuid4().hex[:12]}",
            target=target,
            analysis_type="compliance_check",
            network=self.config.blockchain.network,
        )

        # Fetch transactions
        txs_data = self.adapter.get_address_transactions(target, limit=100)
        transactions = [Transaction.from_dict(tx_data) for tx_data in txs_data]

        # Check 1: Sanctions screening
        sanctions_result = self._check_sanctions(target, transactions, result)

        # Check 2: Structuring detection
        structuring_result = self._check_structuring(target, transactions, result)

        # Check 3: FATF Travel Rule
        travel_rule_result = self._check_travel_rule(target, transactions, result)

        # Check 4: Known entity risk
        entity_risk = self._check_entity_risk(target, result)

        # Check 5: Rapid movement detection
        rapid_movement = self._check_rapid_movement(target, transactions, result)

        # Check 6: Dormant account activation
        dormant_result = self._check_dormant_activation(target, transactions, result)

        # Build comprehensive compliance result
        compliance = ComplianceResult(
            result_id=f"comp_{uuid.uuid4().hex[:8]}",
            entity=target,
            jurisdiction=", ".join(self.config.compliance.jurisdictions),
        )

        if sanctions_result.get("has_sanctioned"):
            compliance.sanctions_match = True
            compliance.add_violation(
                "OFAC_SANCTIONS", "Address matches sanctioned entity list",
                SeverityLevel.CRITICAL
            )
            compliance.reporting_required = True
            compliance.recommended_actions.append("File OFAC report immediately")
            compliance.recommended_actions.append("Freeze related assets")

        if structuring_result:
            compliance.add_violation(
                "STRUCTURING",
                f"{len(structuring_result)} potential structuring patterns detected",
                SeverityLevel.HIGH
            )
            compliance.reporting_required = True
            compliance.recommended_actions.append("File Suspicious Activity Report (SAR)")

        if travel_rule_result:
            compliance.add_warning(
                "FATF_TRAVEL_RULE",
                f"{len(travel_rule_result)} transactions may require Travel Rule compliance"
            )
            compliance.recommended_actions.append("Verify originator/beneficiary information")

        compliance.recommended_actions.append("Continue monitoring for changes in activity pattern")
        result.compliance_results.append(compliance)

        # Calculate risk score
        self._calculate_risk_score(result, compliance)

        return result

    def _check_sanctions(self, address: str, transactions: List[Transaction],
                         result: AnalysisResult) -> Dict[str, Any]:
        """Screen address and related addresses against sanctions lists."""
        # Check the target address
        screen_result = self.sanctions_screener.screen_address(address)

        # Check all addresses in transactions
        related_sanctioned = []
        for tx in transactions:
            tx_screen = self.sanctions_screener.screen_transaction(tx)
            if tx_screen["has_sanctioned"]:
                related_sanctioned.append({
                    "tx_hash": tx.tx_hash,
                    "inputs": tx_screen["sanctioned_inputs"],
                    "outputs": tx_screen["sanctioned_outputs"],
                })

        has_sanctioned = screen_result["is_sanctioned"] or bool(related_sanctioned)

        if has_sanctioned:
            finding = self.create_finding(
                title="Sanctions match detected",
                description=f"Address or related addresses match sanctions lists. "
                           f"Direct match: {screen_result['is_sanctioned']}. "
                           f"Related matches: {len(related_sanctioned)}.",
                severity=SeverityLevel.CRITICAL,
                category=RiskCategory.SANCTIONS_EVASION,
                confidence=0.95,
                recommendation="Immediately file OFAC report and freeze related assets.",
                affected_addresses=[address],
            )
            result.add_finding(finding)

        result.agent_results["sanctions"] = {
            "direct_match": screen_result["is_sanctioned"],
            "related_matches": len(related_sanctioned),
            "has_sanctioned": has_sanctioned,
        }

        return {"has_sanctioned": has_sanctioned, "related": related_sanctioned}

    def _check_structuring(self, address: str, transactions: List[Transaction],
                            result: AnalysisResult) -> List[Dict[str, Any]]:
        """Check for transaction structuring patterns."""
        violations = self.structuring_detector.detect_structuring(transactions, address)

        for violation in violations:
            finding = self.create_finding(
                title="Potential transaction structuring detected",
                description=f"{violation['transaction_count']} transactions totaling "
                           f"{violation['total_value']:.2f} made within "
                           f"{violation['time_span_hours']:.1f} hours, each below the "
                           f"{violation['threshold']:.2f} reporting threshold.",
                severity=SeverityLevel.HIGH,
                category=RiskCategory.STRUCTURING,
                confidence=0.8,
                recommendation="File Suspicious Activity Report (SAR) for potential structuring.",
                affected_addresses=[address],
            )
            result.add_finding(finding)

        result.agent_results["structuring"] = {
            "violations_found": len(violations),
            "threshold": self.structuring_detector.threshold,
        }

        return violations

    def _check_travel_rule(self, address: str, transactions: List[Transaction],
                            result: AnalysisResult) -> List[Dict[str, Any]]:
        """Check FATF Travel Rule compliance."""
        violations = self.travel_rule_checker.check_compliance(transactions, address)

        if violations:
            finding = self.create_finding(
                title="FATF Travel Rule compliance required",
                description=f"{len(violations)} transactions exceed the "
                           f"${self.travel_rule_checker.threshold:,.2f} Travel Rule threshold "
                           f"and require originator/beneficiary information.",
                severity=SeverityLevel.MEDIUM,
                category=RiskCategory.UNUSUAL_ACTIVITY,
                confidence=0.9,
                recommendation="Verify and collect originator/beneficiary information for flagged transactions.",
                affected_addresses=[address],
            )
            result.add_finding(finding)

        result.agent_results["travel_rule"] = {
            "violations_found": len(violations),
            "threshold": self.travel_rule_checker.threshold,
        }

        return violations

    def _check_entity_risk(self, address: str, result: AnalysisResult) -> float:
        """Check risk level of known entity types."""
        risk_score = 0.0

        # Check if address is known exchange
        if address in KNOWN_EXCHANGES:
            result.agent_results["entity_risk"] = {
                "entity_type": "exchange",
                "entity_name": KNOWN_EXCHANGES[address],
                "risk_modifier": 0.3,
            }
            risk_score = 30.0

        # Check if address is known mixer
        if address in KNOWN_MIXERS:
            finding = self.create_finding(
                title="Known mixer/tumbler address detected",
                description=f"Address is associated with known mixer service: {KNOWN_MIXERS[address]}",
                severity=SeverityLevel.CRITICAL,
                category=RiskCategory.MIXER_USAGE,
                confidence=0.95,
                recommendation="Investigate source of funds and file SAR if warranted.",
                affected_addresses=[address],
            )
            result.add_finding(finding)
            risk_score = 95.0

        return risk_score

    def _check_rapid_movement(self, address: str, transactions: List[Transaction],
                               result: AnalysisResult) -> Dict[str, Any]:
        """Detect rapid movement of funds (receive and immediately send)."""
        if len(transactions) < 2:
            return {"rapid_movements": 0}

        sorted_txs = sorted(transactions, key=lambda t: t.timestamp)
        rapid_movements = []

        for i in range(len(sorted_txs) - 1):
            tx1 = sorted_txs[i]
            tx2 = sorted_txs[i + 1]

            # Check if receiving followed quickly by sending
            received = any(out.address == address for out in tx1.outputs)
            sent = any(inp.address == address for inp in tx2.inputs)

            if received and sent:
                time_diff = (tx2.timestamp - tx1.timestamp).total_seconds()
                if time_diff < 3600:  # Less than 1 hour
                    amount = sum(out.value for out in tx1.outputs if out.address == address)
                    rapid_movements.append({
                        "receive_tx": tx1.tx_hash,
                        "send_tx": tx2.tx_hash,
                        "time_seconds": time_diff,
                        "amount": amount,
                    })

        if rapid_movements:
            total_rapid = sum(m["amount"] for m in rapid_movements)
            threshold = self.config.compliance.suspicious_activity_thresholds.get("rapid_movement", 50000)

            if total_rapid > threshold:
                finding = self.create_finding(
                    title="Rapid fund movement detected",
                    description=f"{len(rapid_movements)} instances of rapid fund movement "
                               f"detected (total: {total_rapid:.2f}). Funds received and "
                               f"transferred within 1 hour.",
                    severity=SeverityLevel.HIGH,
                    category=RiskCategory.MONEY_LAUNDERING,
                    confidence=0.75,
                    recommendation="Investigate if rapid movement indicates layering activity.",
                    affected_addresses=[address],
                )
                result.add_finding(finding)

        result.agent_results["rapid_movement"] = {
            "movements_found": len(rapid_movements),
            "total_value": sum(m["amount"] for m in rapid_movements),
        }

        return {"rapid_movements": len(rapid_movements), "details": rapid_movements}

    def _check_dormant_activation(self, address: str, transactions: List[Transaction],
                                    result: AnalysisResult) -> Dict[str, Any]:
        """Check for dormant account activation (long inactive then sudden activity)."""
        if len(transactions) < 2:
            return {"is_dormant_activation": False}

        sorted_txs = sorted(transactions, key=lambda t: t.timestamp)

        # Find gaps > 180 days
        for i in range(1, len(sorted_txs)):
            gap = (sorted_txs[i].timestamp - sorted_txs[i - 1].timestamp).days
            if gap >= 180:
                # Check if recent activity is high-value
                recent_value = sum(
                    out.value for out in sorted_txs[i].outputs
                    if out.address == address
                )
                threshold = self.config.compliance.suspicious_activity_thresholds.get(
                    "dormant_activation", 25000
                )

                if recent_value > threshold:
                    finding = self.create_finding(
                        title="Dormant account activation detected",
                        description=f"Account dormant for {gap} days then activated with "
                                   f"transaction of {recent_value:.2f}.",
                        severity=SeverityLevel.MEDIUM,
                        category=RiskCategory.UNUSUAL_ACTIVITY,
                        confidence=0.65,
                        recommendation="Investigate reason for dormant activation and source of new funds.",
                        affected_addresses=[address],
                    )
                    result.add_finding(finding)
                    return {"is_dormant_activation": True, "dormant_days": gap, "value": recent_value}

        return {"is_dormant_activation": False}

    def _calculate_risk_score(self, result: AnalysisResult,
                               compliance: ComplianceResult) -> None:
        """Calculate compliance risk score."""
        risk = result.risk_score

        # Violations impact
        violation_count = len(compliance.violations)
        risk.add_factor(
            "compliance_violations",
            min(100, violation_count * 30),
            0.4,
            f"{violation_count} compliance violations found"
        )

        # Sanctions match
        if compliance.sanctions_match:
            risk.add_factor("sanctions_match", 100, 0.3, "Address matches sanctions list")

        # Warnings
        warning_count = len(compliance.warnings)
        risk.add_factor(
            "compliance_warnings",
            min(80, warning_count * 15),
            0.3,
            f"{warning_count} compliance warnings"
        )

        risk.confidence = 0.85
