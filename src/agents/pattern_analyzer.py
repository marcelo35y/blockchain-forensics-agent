"""
PatternAnalyzer Agent — Suspicious pattern detection in blockchain transactions.

Detects patterns including:
- Mixing/Tumbling patterns (equal outputs, multiple hops)
- Layering (complex fund flows to obscure origin)
- Structuring (breaking up transactions)
- Round-tripping (funds returning to origin)
- Peel chains (sequential splitting)
- Fan-out/Fan-in patterns
- CoinJoin detection
- Sybil attack patterns
"""

import uuid
import math
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import defaultdict

from src.agents.base_agent import BaseAgent
from src.models.transaction import Transaction
from src.models.analysis import (
    AnalysisResult, Finding, PatternMatch, RiskScore,
    SeverityLevel, RiskCategory,
)
from src.utils.graph_engine import TransactionGraph
from src.utils.blockchain_adapter import MockBlockchainAdapter, BlockchainAdapter
from src.config import AgentConfig


logger = logging.getLogger(__name__)


class MixingDetector:
    """
    Detect mixing/tumbling service patterns.
    Mixing typically involves:
    - Many inputs from different sources
    - Many outputs to different destinations
    - Equal or similar output values
    - Round or near-round amounts
    - High number of outputs relative to inputs
    """

    def __init__(self, config: Dict[str, float] = None):
        self.config = config or {
            "equal_output_values": 0.7,
            "multiple_inputs_outputs": 0.6,
            "round_amounts": 0.3,
            "temporal_clustering": 0.5,
        }

    def analyze_transaction(self, tx: Transaction) -> Dict[str, Any]:
        """Analyze a single transaction for mixing indicators."""
        indicators = []
        score = 0.0

        # Check for many inputs and outputs
        if tx.num_inputs >= 3 and tx.num_outputs >= 3:
            indicators.append({
                "type": "multiple_inputs_outputs",
                "description": f"{tx.num_inputs} inputs and {tx.num_outputs} outputs",
                "score": self.config.get("multiple_inputs_outputs", 0.6),
            })
            score += self.config.get("multiple_inputs_outputs", 0.6)

        # Check for equal output values
        output_values = [out.value for out in tx.outputs]
        if len(output_values) >= 3:
            unique_values = set(round(v, 8) for v in output_values)
            if len(unique_values) <= len(output_values) * 0.3:
                indicators.append({
                    "type": "equal_output_values",
                    "description": f"{len(output_values)} outputs but only {len(unique_values)} unique values",
                    "score": self.config.get("equal_output_values", 0.7),
                })
                score += self.config.get("equal_output_values", 0.7)

        # Check for round amounts
        round_count = sum(1 for v in output_values if abs(v - round(v, 0)) < 0.0001)
        if len(output_values) > 0 and round_count / len(output_values) > 0.5:
            indicators.append({
                "type": "round_amounts",
                "description": f"{round_count}/{len(output_values)} outputs have round amounts",
                "score": self.config.get("round_amounts", 0.3),
            })
            score += self.config.get("round_amounts", 0.3)

        # Check entropy of output addresses
        output_addrs = [out.address for out in tx.outputs]
        if self._check_address_diversity(output_addrs):
            indicators.append({
                "type": "address_diversity",
                "description": "High diversity in output addresses",
                "score": 0.4,
            })
            score += 0.4

        return {
            "is_mixer_like": score >= 1.0,
            "confidence": min(1.0, score / 2.0),
            "score": score,
            "indicators": indicators,
        }

    def _check_address_diversity(self, addresses: List[str]) -> bool:
        """Check if addresses show high diversity (mixing indicator)."""
        if len(addresses) < 3:
            return False
        # Check prefix diversity
        prefixes = set(addr[:4] for addr in addresses)
        return len(prefixes) >= len(addresses) * 0.5

    def detect_mixer_pattern(self, transactions: List[Transaction]) -> Dict[str, Any]:
        """Analyze a sequence of transactions for mixing patterns."""
        mixer_txs = []
        for tx in transactions:
            result = self.analyze_transaction(tx)
            if result["is_mixer_like"]:
                mixer_txs.append({
                    "tx_hash": tx.tx_hash,
                    "confidence": result["confidence"],
                    "indicators": result["indicators"],
                })

        return {
            "mixing_detected": len(mixer_txs) >= 2,
            "mixer_transactions": mixer_txs,
            "total_suspicious": len(mixer_txs),
            "overall_confidence": (
                sum(t["confidence"] for t in mixer_txs) / len(mixer_txs)
                if mixer_txs else 0.0
            ),
        }


class LayeringDetector:
    """
    Detect layering patterns (complex flows to obscure fund origins).
    Layering involves multiple hops through different wallets to make
    tracing difficult.
    """

    def __init__(self, min_hops: int = 3, threshold: float = 0.6):
        self.min_hops = min_hops
        self.threshold = threshold

    def detect_layering(self, graph: TransactionGraph, address: str,
                        max_depth: int = 10) -> Dict[str, Any]:
        """Detect layering patterns from an address."""
        # Trace through the graph
        visited: Dict[str, Dict[str, Any]] = {}
        self._dfs_trace(graph, address, 0, max_depth, visited, [])

        if len(visited) < self.min_hops:
            return {"layering_detected": False, "hop_count": len(visited)}

        # Analyze flow characteristics
        depth_distribution = defaultdict(int)
        for info in visited.values():
            depth_distribution[info["depth"]] += 1

        # Check for branching at each level
        branching_score = 0.0
        for depth, count in depth_distribution.items():
            if count > 1:
                branching_score += min(1.0, count / 5.0)

        # Check for value preservation (money flowing through without significant change)
        values = [info.get("value", 0) for info in visited.values() if info.get("value", 0) > 0]
        value_preservation = 0.0
        if len(values) >= 2:
            avg = sum(values) / len(values)
            variance = sum((v - avg) ** 2 for v in values) / len(values)
            cv = (variance ** 0.5) / avg if avg > 0 else 0
            value_preservation = max(0, 1.0 - cv)

        layering_score = (
            min(1.0, len(visited) / 10.0) * 0.4 +
            branching_score * 0.3 +
            value_preservation * 0.3
        )

        return {
            "layering_detected": layering_score >= self.threshold,
            "layering_score": layering_score,
            "hop_count": len(visited),
            "max_depth": max(info["depth"] for info in visited.values()),
            "depth_distribution": dict(depth_distribution),
            "branching_score": branching_score,
            "value_preservation": value_preservation,
        }

    def _dfs_trace(self, graph: TransactionGraph, address: str, depth: int,
                    max_depth: int, visited: Dict[str, Dict[str, Any]],
                    path: List[str]) -> None:
        """DFS traversal for layering detection."""
        if depth > max_depth or address in visited:
            return

        node = graph.nodes.get(address)
        visited[address] = {
            "depth": depth,
            "value": node.total_in if node else 0,
            "path": list(path),
        }

        for edge in graph.get_outgoing_edges(address):
            self._dfs_trace(graph, edge.target, depth + 1, max_depth,
                          visited, path + [address])


class PeelChainDetector:
    """
    Detect peel chain patterns.
    A peel chain is a series of transactions where each transaction
    sends most funds forward and peels off a small amount.
    """

    def __init__(self, min_length: int = 3, peel_ratio_range: Tuple[float, float] = (0.01, 0.2)):
        self.min_length = min_length
        self.peel_ratio_range = peel_ratio_range

    def detect_peel_chain(self, transactions: List[Transaction],
                          source_address: str) -> Dict[str, Any]:
        """Detect peel chain patterns starting from a source address."""
        chains = []
        current_chain: List[Dict[str, Any]] = []
        current_address = source_address

        sorted_txs = sorted(transactions, key=lambda t: t.timestamp)

        for tx in sorted_txs:
            # Check if this address is an input
            is_input = any(inp.address == current_address for inp in tx.inputs)
            if not is_input:
                continue

            # Check if transaction has exactly 2 outputs (peel pattern)
            if len(tx.outputs) != 2:
                if len(current_chain) >= self.min_length:
                    chains.append(list(current_chain))
                current_chain = []
                continue

            # Identify peel output vs. continuation
            total_output = sum(out.value for out in tx.outputs)
            for out in tx.outputs:
                peel_ratio = out.value / total_output if total_output > 0 else 0

                if self.peel_ratio_range[0] <= peel_ratio <= self.peel_ratio_range[1]:
                    # This is the "peeled" amount
                    current_chain.append({
                        "tx_hash": tx.tx_hash,
                        "peel_address": out.address,
                        "peel_value": out.value,
                        "peel_ratio": peel_ratio,
                        "timestamp": tx.timestamp.isoformat(),
                    })
                else:
                    # This is the continuation
                    current_address = out.address

        # Check final chain
        if len(current_chain) >= self.min_length:
            chains.append(current_chain)

        return {
            "peel_chain_detected": len(chains) > 0,
            "chains": chains,
            "chain_count": len(chains),
            "longest_chain": max(len(c) for c in chains) if chains else 0,
            "total_peeled": sum(
                sum(item["peel_value"] for item in chain)
                for chain in chains
            ),
        }


class RoundTripDetector:
    """Detect round-tripping patterns where funds return to the origin."""

    def __init__(self, time_window_hours: int = 48):
        self.time_window_hours = time_window_hours

    def detect_round_trip(self, graph: TransactionGraph, address: str,
                          max_depth: int = 6) -> Dict[str, Any]:
        """Detect if funds sent from an address return to it."""
        cycles = graph.detect_cycles(address, max_depth)

        round_trips = []
        for cycle in cycles:
            # Calculate value flow
            cycle_value = 0.0
            for i in range(len(cycle) - 1):
                edges = graph._edge_index.get((cycle[i], cycle[i + 1]), [])
                for edge_id in edges:
                    if edge_id in graph.edges:
                        cycle_value = max(cycle_value, graph.edges[edge_id].value)

            round_trips.append({
                "path": cycle,
                "hop_count": len(cycle) - 1,
                "estimated_value": cycle_value,
            })

        return {
            "round_trip_detected": len(round_trips) > 0,
            "round_trips": round_trips,
            "trip_count": len(round_trips),
            "shortest_trip": min(len(rt["path"]) for rt in round_trips) if round_trips else 0,
        }


class PatternAnalyzer(BaseAgent):
    """
    Agent for detecting suspicious patterns in blockchain transactions.
    Identifies money laundering, mixing, layering, and other suspicious patterns.
    """

    AGENT_NAME = "PatternAnalyzer"
    AGENT_VERSION = "1.0.0"
    AGENT_DESCRIPTION = "Detects mixing, layering, structuring, round-tripping, and peel chains"

    def __init__(self, config: Optional[AgentConfig] = None, adapter: Optional[BlockchainAdapter] = None):
        super().__init__(config)
        self.adapter = adapter or MockBlockchainAdapter(
            network=self.config.blockchain.network
        )
        self.mixing_detector = MixingDetector(self.config.patterns.mixing_indicators)
        self.layering_detector = LayeringDetector(
            min_hops=self.config.patterns.layering_hops,
            threshold=self.config.patterns.layering_threshold,
        )
        self.peel_chain_detector = PeelChainDetector(
            min_length=self.config.patterns.peel_chain_min_length,
        )
        self.round_trip_detector = RoundTripDetector(
            time_window_hours=self.config.patterns.round_trip_time_window,
        )

    def validate_input(self, target: str) -> bool:
        """Validate target is a valid address."""
        return bool(target and len(target) >= 10)

    def analyze(self, target: str, context: Dict[str, Any] = None) -> AnalysisResult:
        """Perform pattern analysis on the target address."""
        context = context or {}
        result = AnalysisResult(
            analysis_id=f"pattern_{uuid.uuid4().hex[:12]}",
            target=target,
            analysis_type="pattern_analysis",
            network=self.config.blockchain.network,
        )

        # Fetch transactions
        txs_data = self.adapter.get_address_transactions(target, limit=200)
        transactions = [Transaction.from_dict(tx_data) for tx_data in txs_data]

        # Build transaction graph
        graph = TransactionGraph()
        for tx in transactions:
            for inp in tx.inputs:
                graph.add_node(inp.address)
            for out in tx.outputs:
                graph.add_node(out.address)
            for inp in tx.inputs:
                for out in tx.outputs:
                    graph.add_edge(inp.address, out.address, out.value,
                                   tx.tx_hash, tx.timestamp)

        # Pattern 1: Mixing detection
        mixing_result = self._detect_mixing(transactions, result)

        # Pattern 2: Layering detection
        layering_result = self._detect_layering(graph, target, result)

        # Pattern 3: Peel chain detection
        peel_result = self._detect_peel_chain(transactions, target, result)

        # Pattern 4: Round-trip detection
        round_trip_result = self._detect_round_trip(graph, target, result)

        # Pattern 5: Fan-out detection
        fan_out_result = self._detect_fan_out(graph, target, result)

        # Pattern 6: Fan-in detection
        fan_in_result = self._detect_fan_in(graph, target, result)

        # Pattern 7: CoinJoin detection
        coinjoin_result = self._detect_coinjoin(transactions, result)

        # Calculate risk score
        self._calculate_risk_score(
            result, mixing_result, layering_result, peel_result,
            round_trip_result, fan_out_result, fan_in_result
        )

        return result

    def _detect_mixing(self, transactions: List[Transaction],
                        result: AnalysisResult) -> Dict[str, Any]:
        """Detect mixing/tumbling patterns."""
        mixing_result = self.mixing_detector.detect_mixer_pattern(transactions)

        if mixing_result["mixing_detected"]:
            pattern = PatternMatch(
                pattern_id=f"mix_{uuid.uuid4().hex[:8]}",
                pattern_type="mixing",
                pattern_name="Cryptocurrency Mixing Pattern",
                description=f"Detected {mixing_result['total_suspicious']} transactions with mixing characteristics",
                confidence=mixing_result["overall_confidence"],
                risk_level=SeverityLevel.HIGH,
                transactions=[t["tx_hash"] for t in mixing_result["mixer_transactions"]],
                amount_involved=sum(
                    sum(out.value for out in tx.outputs)
                    for tx in transactions
                    if any(m["tx_hash"] == tx.tx_hash for m in mixing_result["mixer_transactions"])
                ),
                indicators=[
                    ind for t in mixing_result["mixer_transactions"]
                    for ind in t.get("indicators", [])
                ],
            )
            result.add_pattern(pattern)

            finding = self.create_finding(
                title="Cryptocurrency mixing pattern detected",
                description=f"Analysis identified {mixing_result['total_suspicious']} transactions "
                           f"exhibiting mixing/tumbling characteristics. Confidence: "
                           f"{mixing_result['overall_confidence']:.2%}.",
                severity=SeverityLevel.HIGH,
                category=RiskCategory.MIXER_USAGE,
                confidence=mixing_result["overall_confidence"],
                recommendation="Investigate the source of funds and purpose of mixing activity.",
            )
            result.add_finding(finding)

        result.agent_results["mixing"] = mixing_result
        return mixing_result

    def _detect_layering(self, graph: TransactionGraph, address: str,
                          result: AnalysisResult) -> Dict[str, Any]:
        """Detect layering patterns."""
        layering_result = self.layering_detector.detect_layering(
            graph, address, max_depth=self.config.blockchain.max_trace_depth
        )

        if layering_result["layering_detected"]:
            pattern = PatternMatch(
                pattern_id=f"layer_{uuid.uuid4().hex[:8]}",
                pattern_type="layering",
                pattern_name="Fund Layering Pattern",
                description=f"Layering detected with {layering_result['hop_count']} hops across "
                           f"{layering_result['max_depth']} depth levels",
                confidence=layering_result["layering_score"],
                risk_level=SeverityLevel.HIGH,
                addresses=[address],
                details=layering_result,
            )
            result.add_pattern(pattern)

            finding = self.create_finding(
                title="Fund layering pattern detected",
                description=f"Funds moved through {layering_result['hop_count']} addresses across "
                           f"{layering_result['max_depth']} levels of indirection. "
                           f"Score: {layering_result['layering_score']:.2f}.",
                severity=SeverityLevel.HIGH,
                category=RiskCategory.MONEY_LAUNDERING,
                confidence=layering_result["layering_score"],
                recommendation="Trace the full flow path and identify the ultimate destination of funds.",
                affected_addresses=[address],
            )
            result.add_finding(finding)

        result.agent_results["layering"] = layering_result
        return layering_result

    def _detect_peel_chain(self, transactions: List[Transaction], address: str,
                            result: AnalysisResult) -> Dict[str, Any]:
        """Detect peel chain patterns."""
        peel_result = self.peel_chain_detector.detect_peel_chain(transactions, address)

        if peel_result["peel_chain_detected"]:
            pattern = PatternMatch(
                pattern_id=f"peel_{uuid.uuid4().hex[:8]}",
                pattern_type="peel_chain",
                pattern_name="Peel Chain Pattern",
                description=f"Peel chain detected with {peel_result['chain_count']} chains, "
                           f"longest: {peel_result['longest_chain']} hops",
                confidence=0.8,
                risk_level=SeverityLevel.HIGH,
                addresses=[address],
                amount_involved=peel_result["total_peeled"],
                details=peel_result,
            )
            result.add_pattern(pattern)

            finding = self.create_finding(
                title="Peel chain pattern detected",
                description=f"Identified {peel_result['chain_count']} peel chains with a total of "
                           f"{peel_result['total_peeled']:.8f} peeled across "
                           f"{peel_result['longest_chain']} sequential transactions.",
                severity=SeverityLevel.HIGH,
                category=RiskCategory.MONEY_LAUNDERING,
                confidence=0.8,
                recommendation="Trace peel chain to identify final destination addresses.",
                affected_addresses=[address],
            )
            result.add_finding(finding)

        result.agent_results["peel_chain"] = peel_result
        return peel_result

    def _detect_round_trip(self, graph: TransactionGraph, address: str,
                            result: AnalysisResult) -> Dict[str, Any]:
        """Detect round-tripping patterns."""
        round_trip_result = self.round_trip_detector.detect_round_trip(graph, address)

        if round_trip_result["round_trip_detected"]:
            pattern = PatternMatch(
                pattern_id=f"rt_{uuid.uuid4().hex[:8]}",
                pattern_type="round_trip",
                pattern_name="Round-Tripping Pattern",
                description=f"Funds return to origin through {round_trip_result['trip_count']} round trips",
                confidence=0.75,
                risk_level=SeverityLevel.MEDIUM,
                addresses=[address],
                details=round_trip_result,
            )
            result.add_pattern(pattern)

            finding = self.create_finding(
                title="Round-tripping pattern detected",
                description=f"Identified {round_trip_result['trip_count']} round-trip patterns where "
                           f"funds return to the originating address. "
                           f"Shortest path: {round_trip_result['shortest_trip']} hops.",
                severity=SeverityLevel.MEDIUM,
                category=RiskCategory.MONEY_LAUNDERING,
                confidence=0.75,
                recommendation="Investigate if round-tripping is intentional obfuscation.",
                affected_addresses=[address],
            )
            result.add_finding(finding)

        result.agent_results["round_trip"] = round_trip_result
        return round_trip_result

    def _detect_fan_out(self, graph: TransactionGraph, address: str,
                         result: AnalysisResult) -> Dict[str, Any]:
        """Detect fan-out distribution patterns."""
        fan_out = graph.find_fan_out(address, threshold=5)

        if fan_out.get("is_fan_out"):
            finding = self.create_finding(
                title="Fan-out distribution pattern detected",
                description=f"Funds distributed to {fan_out['count']} addresses from a single source. "
                           f"Total: {fan_out['total_value']:.8f}. "
                           f"{'Uniform distribution detected.' if fan_out.get('is_uniform') else 'Variable amounts.'}",
                severity=SeverityLevel.MEDIUM,
                category=RiskCategory.STRUCTURING,
                confidence=0.6,
                recommendation="Investigate if fan-out indicates structuring or distribution to beneficiaries.",
                affected_addresses=[address],
            )
            result.add_finding(finding)

        result.agent_results["fan_out"] = fan_out
        return fan_out

    def _detect_fan_in(self, graph: TransactionGraph, address: str,
                         result: AnalysisResult) -> Dict[str, Any]:
        """Detect fan-in consolidation patterns."""
        fan_in = graph.find_fan_in(address, threshold=5)

        if fan_in.get("is_fan_in"):
            finding = self.create_finding(
                title="Fan-in consolidation pattern detected",
                description=f"Funds consolidated from {fan_in['count']} addresses into a single destination. "
                           f"Total: {fan_in['total_value']:.8f}.",
                severity=SeverityLevel.MEDIUM,
                category=RiskCategory.MONEY_LAUNDERING,
                confidence=0.6,
                recommendation="Investigate the source of consolidated funds.",
                affected_addresses=[address],
            )
            result.add_finding(finding)

        result.agent_results["fan_in"] = fan_in
        return fan_in

    def _detect_coinjoin(self, transactions: List[Transaction],
                          result: AnalysisResult) -> Dict[str, Any]:
        """Detect CoinJoin-style collaborative transactions."""
        coinjoin_txs = []

        for tx in transactions:
            # CoinJoin characteristics: multiple equal-value outputs
            if tx.num_inputs >= 3 and tx.num_outputs >= 3:
                output_values = [out.value for out in tx.outputs]
                unique_values = set(round(v, 6) for v in output_values)

                # Check for multiple outputs with same value (CoinJoin signature)
                for value in unique_values:
                    count = sum(1 for v in output_values if abs(v - value) < 0.000001)
                    if count >= 3:
                        coinjoin_txs.append({
                            "tx_hash": tx.tx_hash,
                            "common_value": value,
                            "matching_outputs": count,
                            "total_outputs": tx.num_outputs,
                            "total_inputs": tx.num_inputs,
                        })
                        break

        if coinjoin_txs:
            finding = self.create_finding(
                title="CoinJoin-style transaction detected",
                description=f"Identified {len(coinjoin_txs)} CoinJoin-style collaborative transactions "
                           f"with multiple equal-value outputs.",
                severity=SeverityLevel.MEDIUM,
                category=RiskCategory.MIXER_USAGE,
                confidence=0.7,
                recommendation="Identify CoinJoin coordinator and participating addresses.",
            )
            result.add_finding(finding)

        result.agent_results["coinjoin"] = {
            "coinjoin_detected": len(coinjoin_txs) > 0,
            "transaction_count": len(coinjoin_txs),
            "transactions": coinjoin_txs,
        }

        return {"coinjoin_detected": bool(coinjoin_txs), "count": len(coinjoin_txs)}

    def _calculate_risk_score(self, result: AnalysisResult, *pattern_results: Any) -> None:
        """Calculate risk score from pattern analysis."""
        risk = result.risk_score

        # Pattern findings
        pattern_count = len(result.patterns)
        risk.add_factor(
            "detected_patterns",
            min(100, pattern_count * 25),
            0.4,
            f"{pattern_count} suspicious patterns detected"
        )

        # High-confidence patterns
        high_conf = sum(1 for p in result.patterns if p.confidence > 0.7)
        risk.add_factor(
            "high_confidence_patterns",
            min(100, high_conf * 30),
            0.3,
            f"{high_conf} high-confidence pattern matches"
        )

        # Finding severity
        critical_findings = len(result.critical_findings)
        high_findings = len(result.high_findings)
        risk.add_factor(
            "finding_severity",
            min(100, critical_findings * 40 + high_findings * 20),
            0.3,
            f"{critical_findings} critical, {high_findings} high severity findings"
        )

        risk.confidence = 0.7
