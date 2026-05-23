"""
TransactionTracer Agent — Multi-hop fund tracing across blockchain networks.

Implements sophisticated fund tracing algorithms including:
- Forward tracing (following funds from source)
- Backward tracing (finding fund origins)
- Taint analysis (tracking tainted coins through mixing)
- Multi-hop path analysis with depth limiting
- Value flow tracking with change detection
"""

import uuid
import hashlib
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any, Tuple
from collections import defaultdict, deque

from src.agents.base_agent import BaseAgent
from src.models.transaction import Transaction, TransactionInput, TransactionOutput
from src.models.analysis import (
    AnalysisResult, Finding, TracingResult, RiskScore,
    SeverityLevel, RiskCategory,
)
from src.utils.graph_engine import TransactionGraph
from src.utils.blockchain_adapter import MockBlockchainAdapter, BlockchainAdapter
from src.config import AgentConfig

logger = logging.getLogger(__name__)


class TaintTracker:
    """
    Tracks tainted funds through multiple transaction hops.
    Implements Bitcoin-style taint analysis to follow money flows.
    """

    def __init__(self, taint_threshold: float = 0.01):
        self.taint_threshold = taint_threshold
        self.taint_scores: Dict[str, float] = {}
        self.taint_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def set_taint(self, address: str, score: float) -> None:
        """Set taint score for an address."""
        self.taint_scores[address] = min(1.0, max(0.0, score))
        self.taint_history[address].append({
            "score": score,
            "timestamp": datetime.utcnow().isoformat(),
            "action": "set",
        })

    def propagate_taint(self, source_address: str, target_address: str,
                        source_value: float, transfer_value: float) -> float:
        """
        Propagate taint from source to target address based on value transfer.
        Uses weighted taint propagation: taint_target = taint_source * (transfer / source_total)
        """
        source_taint = self.taint_scores.get(source_address, 0.0)
        if source_taint < self.taint_threshold:
            return 0.0

        # Calculate taint proportion
        if source_value > 0:
            proportion = min(1.0, transfer_value / source_value)
        else:
            proportion = 1.0

        propagated_taint = source_taint * proportion

        # Update target taint (max of existing and new)
        existing_taint = self.taint_scores.get(target_address, 0.0)
        new_taint = max(existing_taint, propagated_taint)

        if new_taint > self.taint_threshold:
            self.taint_scores[target_address] = new_taint
            self.taint_history[target_address].append({
                "score": new_taint,
                "source": source_address,
                "propagated_from": source_taint,
                "proportion": proportion,
                "timestamp": datetime.utcnow().isoformat(),
                "action": "propagate",
            })

        return new_taint

    def get_tainted_addresses(self, threshold: float = 0.1) -> Dict[str, float]:
        """Get all addresses with taint above threshold."""
        return {
            addr: score for addr, score in self.taint_scores.items()
            if score >= threshold
        }

    def get_taint_path(self, address: str) -> List[Dict[str, Any]]:
        """Get the taint propagation history for an address."""
        return self.taint_history.get(address, [])


class FlowAnalyzer:
    """
    Analyzes fund flow patterns in transaction graphs.
    Identifies split, merge, peel chain, and circular patterns.
    """

    def __init__(self):
        self.flow_patterns: List[Dict[str, Any]] = []

    def analyze_flow(self, graph: TransactionGraph, source: str,
                     max_depth: int = 10) -> Dict[str, Any]:
        """Comprehensive flow analysis from a source address."""
        result = {
            "source": source,
            "forward_flow": self._trace_forward(graph, source, max_depth),
            "flow_metrics": self._calculate_flow_metrics(graph, source),
            "convergence_points": self._find_convergence_points(graph, source, max_depth),
            "terminal_addresses": self._find_terminal_addresses(graph, source, max_depth),
            "flow_complexity": 0.0,
        }

        # Calculate flow complexity score
        forward = result["forward_flow"]
        result["flow_complexity"] = min(1.0, (
            forward.get("unique_addresses", 0) * 0.1 +
            forward.get("max_depth", 0) * 0.15 +
            len(result["convergence_points"]) * 0.2 +
            len(result["terminal_addresses"]) * 0.05
        ))

        return result

    def _trace_forward(self, graph: TransactionGraph, source: str,
                       max_depth: int) -> Dict[str, Any]:
        """Trace funds forward from source through the graph."""
        visited: Dict[str, Dict[str, Any]] = {}
        queue = deque([(source, 0, 0.0, [])])

        while queue:
            address, depth, cumulative_value, path = queue.popleft()

            if address in visited or depth > max_depth:
                continue

            visited[address] = {
                "address": address,
                "depth": depth,
                "cumulative_value": cumulative_value,
                "path_length": len(path),
            }

            for edge in graph.get_outgoing_edges(address):
                if edge.target not in visited:
                    queue.append((
                        edge.target,
                        depth + 1,
                        cumulative_value + edge.value,
                        path + [address],
                    ))

        return {
            "unique_addresses": len(visited),
            "max_depth": max((v["depth"] for v in visited.values()), default=0),
            "total_value_traced": sum(v["cumulative_value"] for v in visited.values()),
            "addresses": visited,
        }

    def _calculate_flow_metrics(self, graph: TransactionGraph,
                                source: str) -> Dict[str, Any]:
        """Calculate various flow metrics."""
        outgoing = graph.get_outgoing_edges(source)
        incoming = graph.get_incoming_edges(source)

        out_values = [e.value for e in outgoing]
        in_values = [e.value for e in incoming]

        return {
            "outgoing_tx_count": len(outgoing),
            "incoming_tx_count": len(incoming),
            "total_outgoing": sum(out_values),
            "total_incoming": sum(in_values),
            "avg_outgoing_value": sum(out_values) / len(out_values) if out_values else 0,
            "avg_incoming_value": sum(in_values) / len(in_values) if in_values else 0,
            "max_single_outgoing": max(out_values) if out_values else 0,
            "max_single_incoming": max(in_values) if in_values else 0,
            "unique_outgoing_targets": len(set(e.target for e in outgoing)),
            "unique_incoming_sources": len(set(e.source for e in incoming)),
            "fan_out_ratio": len(outgoing) / max(1, len(incoming)),
        }

    def _find_convergence_points(self, graph: TransactionGraph, source: str,
                                 max_depth: int) -> List[Dict[str, Any]]:
        """Find addresses where funds converge (merge points)."""
        convergence = []
        visited = set()
        queue = deque([(source, 0)])

        while queue:
            address, depth = queue.popleft()
            if address in visited or depth > max_depth:
                continue
            visited.add(address)

            incoming = graph.get_incoming_edges(address)
            if len(incoming) >= 3:
                convergence.append({
                    "address": address,
                    "depth": depth,
                    "incoming_count": len(incoming),
                    "total_incoming_value": sum(e.value for e in incoming),
                    "unique_sources": len(set(e.source for e in incoming)),
                })

            for edge in graph.get_outgoing_edges(address):
                if edge.target not in visited:
                    queue.append((edge.target, depth + 1))

        return convergence

    def _find_terminal_addresses(self, graph: TransactionGraph, source: str,
                                 max_depth: int) -> List[Dict[str, Any]]:
        """Find terminal addresses (no outgoing transactions)."""
        terminals = []
        visited = set()
        queue = deque([(source, 0)])

        while queue:
            address, depth = queue.popleft()
            if address in visited or depth > max_depth:
                continue
            visited.add(address)

            outgoing = graph.get_outgoing_edges(address)
            if not outgoing and address != source:
                incoming = graph.get_incoming_edges(address)
                total_received = sum(e.value for e in incoming)
                terminals.append({
                    "address": address,
                    "depth": depth,
                    "total_received": total_received,
                    "incoming_count": len(incoming),
                })

            for edge in outgoing:
                if edge.target not in visited:
                    queue.append((edge.target, depth + 1))

        return terminals


class TransactionTracer(BaseAgent):
    """
    Agent for multi-hop transaction tracing and fund flow analysis.
    Traces cryptocurrency movements through blockchain networks.
    """

    AGENT_NAME = "TransactionTracer"
    AGENT_VERSION = "1.0.0"
    AGENT_DESCRIPTION = "Multi-hop fund tracing with taint analysis"

    def __init__(self, config: Optional[AgentConfig] = None, adapter: Optional[BlockchainAdapter] = None):
        super().__init__(config)
        self.adapter = adapter or MockBlockchainAdapter(
            network=self.config.blockchain.network
        )
        self.taint_tracker = TaintTracker()
        self.flow_analyzer = FlowAnalyzer()
        self._trace_cache: Dict[str, TracingResult] = {}

    def validate_input(self, target: str) -> bool:
        """Validate that target is a valid transaction hash or address."""
        if not target or len(target) < 10:
            return False
        # Accept hex strings (tx hashes) or alphanumeric (addresses)
        return all(c in '0123456789abcdefABCDEF' for c in target) or target.isalnum()

    def analyze(self, target: str, context: Dict[str, Any] = None) -> AnalysisResult:
        """
        Perform comprehensive transaction tracing analysis.
        
        Args:
            target: Transaction hash or address to trace
            context: Additional context (e.g., known entities, tags)
        """
        context = context or {}
        result = AnalysisResult(
            analysis_id=f"trace_{uuid.uuid4().hex[:12]}",
            target=target,
            analysis_type="transaction_trace",
            network=self.config.blockchain.network,
        )

        max_depth = context.get("max_depth", self.config.blockchain.max_trace_depth)

        # Determine if target is tx hash or address
        is_tx = len(target) == 64 and all(c in '0123456789abcdefABCDEF' for c in target)

        if is_tx:
            self._trace_from_transaction(target, result, max_depth, context)
        else:
            self._trace_from_address(target, result, max_depth, context)

        # Calculate overall risk score
        self._calculate_risk_score(result)

        return result

    def _trace_from_transaction(self, tx_hash: str, result: AnalysisResult,
                                max_depth: int, context: Dict[str, Any]) -> None:
        """Trace funds starting from a transaction."""
        self.logger.info(f"Tracing from transaction {tx_hash[:16]}...")

        # Fetch transaction data
        tx_data = self.adapter.get_transaction(tx_hash)
        tx = Transaction.from_dict(tx_data)

        # Build transaction graph
        graph = TransactionGraph()
        self._build_graph_from_tx(tx, graph)

        # Forward trace from output addresses
        trace_result = TracingResult(
            trace_id=f"trace_{uuid.uuid4().hex[:8]}",
            source_address=tx_hash,
            network=self.config.blockchain.network,
        )

        for output in tx.outputs:
            # Forward trace each output
            flow = self.flow_analyzer.analyze_flow(graph, output.address, max_depth)
            trace_result.max_depth_reached = max(
                trace_result.max_depth_reached,
                flow["forward_flow"]["max_depth"]
            )
            trace_result.total_addresses += flow["forward_flow"]["unique_addresses"]
            trace_result.total_value_traced += flow["forward_flow"]["total_value_traced"]

            # Track taint
            self.taint_tracker.set_taint(output.address, 1.0)
            self._propagate_taint_through_flow(graph, output.address, max_depth, trace_result)

            # Build paths
            for addr, info in flow["forward_flow"]["addresses"].items():
                if info["depth"] > 0:
                    trace_result.add_path([{
                        "address": addr,
                        "depth": info["depth"],
                        "value": info["cumulative_value"],
                    }])

        trace_result.taint_analysis = self.taint_tracker.get_tainted_addresses(0.05)
        result.tracing_results.append(trace_result)

        # Generate findings
        self._generate_tracing_findings(trace_result, result)

    def _trace_from_address(self, address: str, result: AnalysisResult,
                            max_depth: int, context: Dict[str, Any]) -> None:
        """Trace funds starting from an address."""
        self.logger.info(f"Tracing from address {address[:16]}...")

        # Fetch address transactions
        txs_data = self.adapter.get_address_transactions(address, limit=50)

        graph = TransactionGraph()
        for tx_data in txs_data:
            tx = Transaction.from_dict(tx_data)
            self._build_graph_from_tx(tx, graph)

        trace_result = TracingResult(
            trace_id=f"trace_{uuid.uuid4().hex[:8]}",
            source_address=address,
            network=self.config.blockchain.network,
        )

        # Forward trace
        flow = self.flow_analyzer.analyze_flow(graph, address, max_depth)
        trace_result.max_depth_reached = flow["forward_flow"]["max_depth"]
        trace_result.total_addresses = flow["forward_flow"]["unique_addresses"]
        trace_result.total_value_traced = flow["forward_flow"]["total_value_traced"]

        # Set initial taint
        self.taint_tracker.set_taint(address, 1.0)
        self._propagate_taint_through_flow(graph, address, max_depth, trace_result)

        trace_result.taint_analysis = self.taint_tracker.get_tainted_addresses(0.05)
        result.tracing_results.append(trace_result)

        self._generate_tracing_findings(trace_result, result)

    def _build_graph_from_tx(self, tx: Transaction, graph: TransactionGraph) -> None:
        """Add transaction data to the graph."""
        for inp in tx.inputs:
            graph.add_node(inp.address)
        for out in tx.outputs:
            graph.add_node(out.address)
        for inp in tx.inputs:
            for out in tx.outputs:
                graph.add_edge(
                    source=inp.address,
                    target=out.address,
                    value=out.value,
                    tx_hash=tx.tx_hash,
                    timestamp=tx.timestamp,
                )

    def _propagate_taint_through_flow(self, graph: TransactionGraph,
                                       source: str, max_depth: int,
                                       trace_result: TracingResult) -> None:
        """Propagate taint scores through the transaction graph."""
        visited = set()
        queue = deque([(source, 0)])

        while queue:
            address, depth = queue.popleft()
            if address in visited or depth > max_depth:
                continue
            visited.add(address)

            node = graph.nodes.get(address)
            if not node:
                continue

            for edge in graph.get_outgoing_edges(address):
                taint = self.taint_tracker.propagate_taint(
                    address, edge.target,
                    node.total_out if node.total_out > 0 else edge.value,
                    edge.value
                )
                if taint > 0.01:
                    queue.append((edge.target, depth + 1))

    def _generate_tracing_findings(self, trace: TracingResult,
                                    result: AnalysisResult) -> None:
        """Generate findings from tracing analysis."""
        # High-risk endpoint findings
        for endpoint in trace.high_risk_endpoints:
            finding = self.create_finding(
                title="Funds traced to high-risk address",
                description=f"Funds traced to high-risk address at depth {endpoint.get('depth', '?')}",
                severity=SeverityLevel.HIGH,
                category=RiskCategory.MONEY_LAUNDERING,
                confidence=0.7,
                recommendation="Investigate the endpoint address for known illicit activity.",
                affected_addresses=[endpoint.get("address", "")],
            )
            result.add_finding(finding)

        # Long chain finding
        if trace.max_depth_reached >= 7:
            finding = self.create_finding(
                title="Extended transaction chain detected",
                description=f"Funds traced through {trace.max_depth_reached} hops, suggesting intentional obfuscation",
                severity=SeverityLevel.MEDIUM,
                category=RiskCategory.MONEY_LAUNDERING,
                confidence=0.6,
                recommendation="Review the full transaction chain for mixing or layering patterns.",
            )
            result.add_finding(finding)

        # Many endpoints finding
        if len(trace.endpoints) > 20:
            finding = self.create_finding(
                title="Broad fund distribution detected",
                description=f"Funds distributed to {len(trace.endpoints)} endpoint addresses",
                severity=SeverityLevel.MEDIUM,
                category=RiskCategory.STRUCTURING,
                confidence=0.5,
                recommendation="Investigate if distribution pattern indicates structuring or layering.",
            )
            result.add_finding(finding)

    def _calculate_risk_score(self, result: AnalysisResult) -> None:
        """Calculate overall risk score from tracing results."""
        risk = result.risk_score

        if result.tracing_results:
            trace = result.tracing_results[0]

            # Factor 1: Number of high-risk endpoints
            if trace.high_risk_endpoints:
                risk.add_factor(
                    "high_risk_endpoints",
                    min(100, len(trace.high_risk_endpoints) * 20),
                    0.3,
                    f"{len(trace.high_risk_endpoints)} high-risk endpoints found"
                )

            # Factor 2: Trace depth
            depth_score = min(100, trace.max_depth_reached * 12)
            risk.add_factor("trace_depth", depth_score, 0.2,
                           f"Maximum trace depth: {trace.max_depth_reached}")

            # Factor 3: Number of addresses involved
            addr_score = min(100, trace.total_addresses * 2)
            risk.add_factor("address_count", addr_score, 0.2,
                           f"{trace.total_addresses} addresses involved")

            # Factor 4: Tainted addresses
            tainted = len(trace.taint_analysis)
            taint_score = min(100, tainted * 5)
            risk.add_factor("tainted_addresses", taint_score, 0.3,
                           f"{tainted} tainted addresses detected")

        risk.confidence = 0.8
