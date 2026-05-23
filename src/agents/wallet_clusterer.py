"""
WalletClusterer Agent — Entity clustering using co-spending, temporal, and behavioral analysis.

Implements multiple clustering heuristics:
- Co-spending analysis (addresses used as inputs in same transaction)
- Temporal analysis (addresses with correlated timing patterns)
- Behavioral analysis (similar transaction patterns)
- Address reuse detection
- Common-input-ownership heuristic
"""

import uuid
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any, Tuple
from collections import defaultdict
import math

from src.agents.base_agent import BaseAgent
from src.models.wallet import Wallet, WalletCluster, WalletType, AddressType
from src.models.transaction import Transaction, TransactionInput, TransactionOutput
from src.models.analysis import AnalysisResult, Finding, RiskScore, SeverityLevel, RiskCategory
from src.utils.blockchain_adapter import MockBlockchainAdapter, BlockchainAdapter
from src.config import AgentConfig


logger = logging.getLogger(__name__)


class CoSpendingAnalyzer:
    """
    Implements the common-input-ownership heuristic.
    Addresses that appear as inputs in the same transaction are likely
    controlled by the same entity.
    """

    def __init__(self):
        self.co_spending_groups: Dict[str, Set[str]] = defaultdict(set)
        self.co_spending_counts: Dict[Tuple[str, str], int] = defaultdict(int)

    def analyze_transactions(self, transactions: List[Transaction]) -> List[Set[str]]:
        """
        Analyze transactions to find co-spending groups.
        Returns list of address sets believed to be controlled by same entity.
        """
        for tx in transactions:
            input_addresses = set(inp.address for inp in tx.inputs)
            if len(input_addresses) > 1:
                # All input addresses likely belong to same entity
                group_id = hashlib.md5(
                    str(sorted(input_addresses)).encode()
                ).hexdigest()[:12]

                for addr in input_addresses:
                    self.co_spending_groups[group_id].add(addr)

                # Track pairwise co-spending
                addr_list = sorted(input_addresses)
                for i in range(len(addr_list)):
                    for j in range(i + 1, len(addr_list)):
                        pair = (addr_list[i], addr_list[j])
                        self.co_spending_counts[pair] += 1

        return list(self.co_spending_groups.values())

    def get_co_spending_score(self, addr1: str, addr2: str) -> float:
        """Calculate co-spending similarity score between two addresses."""
        pair = tuple(sorted([addr1, addr2]))
        count = self.co_spending_counts.get(pair, 0)
        if count == 0:
            return 0.0
        # Logarithmic scaling to avoid over-weighting frequent co-spending
        return min(1.0, math.log1p(count) / 5.0)

    def find_clusters(self, min_confidence: float = 0.5) -> List[Set[str]]:
        """Find address clusters based on co-spending analysis."""
        # Build adjacency graph
        adjacency: Dict[str, Set[str]] = defaultdict(set)
        for (a1, a2), count in self.co_spending_counts.items():
            if count >= 1:
                adjacency[a1].add(a2)
                adjacency[a2].add(a1)

        # Find connected components
        visited = set()
        clusters = []

        for address in adjacency:
            if address in visited:
                continue
            cluster = set()
            stack = [address]
            while stack:
                current = stack.pop()
                if current in visited:
                    continue
                visited.add(current)
                cluster.add(current)
                for neighbor in adjacency[current]:
                    if neighbor not in visited:
                        stack.append(neighbor)
            if len(cluster) >= 2:
                clusters.append(cluster)

        return clusters


class TemporalAnalyzer:
    """
    Analyzes temporal patterns to identify wallets with correlated timing.
    Addresses that transact at similar times may be controlled by same entity.
    """

    def __init__(self, window_minutes: int = 30):
        self.window_minutes = window_minutes
        self.address_timestamps: Dict[str, List[datetime]] = defaultdict(list)

    def add_transaction(self, tx: Transaction) -> None:
        """Record transaction timestamps for involved addresses."""
        for addr in tx.involved_addresses:
            self.address_timestamps[addr].append(tx.timestamp)

    def calculate_temporal_correlation(self, addr1: str, addr2: str) -> float:
        """
        Calculate temporal correlation between two addresses.
        Returns score 0.0-1.0 based on timing overlap.
        """
        timestamps1 = sorted(self.address_timestamps.get(addr1, []))
        timestamps2 = sorted(self.address_timestamps.get(addr2, []))

        if not timestamps1 or not timestamps2:
            return 0.0

        matches = 0
        window = timedelta(minutes=self.window_minutes)

        for t1 in timestamps1:
            for t2 in timestamps2:
                if abs((t1 - t2).total_seconds()) < window.total_seconds():
                    matches += 1
                    break

        total = max(len(timestamps1), len(timestamps2))
        return matches / total if total > 0 else 0.0

    def find_temporal_clusters(self, addresses: List[str],
                               threshold: float = 0.5) -> List[Set[str]]:
        """Find clusters of temporally correlated addresses."""
        clusters = []
        visited = set()

        for i, addr1 in enumerate(addresses):
            if addr1 in visited:
                continue
            cluster = {addr1}
            for addr2 in addresses[i + 1:]:
                if addr2 in visited:
                    continue
                corr = self.calculate_temporal_correlation(addr1, addr2)
                if corr >= threshold:
                    cluster.add(addr2)
                    visited.add(addr2)
            if len(cluster) >= 2:
                clusters.append(cluster)
            visited.add(addr1)

        return clusters


class BehavioralAnalyzer:
    """
    Analyzes behavioral patterns of addresses to identify common ownership.
    Considers: transaction amounts, fee preferences, timing, UTXO management.
    """

    def __init__(self):
        self.address_profiles: Dict[str, Dict[str, Any]] = {}

    def build_profile(self, address: str, transactions: List[Transaction]) -> Dict[str, Any]:
        """Build a behavioral profile for an address."""
        profile = {
            "address": address,
            "tx_count": len(transactions),
            "avg_value": 0.0,
            "std_value": 0.0,
            "avg_fee": 0.0,
            "preferred_hour": -1,
            "input_output_ratio": 0.0,
            "address_type_usage": defaultdict(int),
            "dust_output_ratio": 0.0,
            "round_amount_ratio": 0.0,
        }

        if not transactions:
            return profile

        values = []
        fees = []
        hours = []
        input_count = 0
        output_count = 0
        dust_count = 0
        round_count = 0

        for tx in transactions:
            for inp in tx.inputs:
                if inp.address == address:
                    values.append(inp.value)
                    input_count += 1
            for out in tx.outputs:
                if out.address == address:
                    values.append(out.value)
                    output_count += 1
                    if out.value < 0.0001:
                        dust_count += 1
                    if out.value == round(out.value, 0):
                        round_count += 1
            fees.append(tx.fee)
            hours.append(tx.timestamp.hour)

        if values:
            avg = sum(values) / len(values)
            profile["avg_value"] = avg
            profile["std_value"] = (sum((v - avg) ** 2 for v in values) / len(values)) ** 0.5

        profile["avg_fee"] = sum(fees) / len(fees) if fees else 0.0
        profile["preferred_hour"] = max(set(hours), key=hours.count) if hours else -1
        profile["input_output_ratio"] = input_count / max(1, output_count)
        profile["dust_output_ratio"] = dust_count / max(1, output_count)
        profile["round_amount_ratio"] = round_count / max(1, len(values))

        self.address_profiles[address] = profile
        return profile

    def calculate_similarity(self, addr1: str, addr2: str) -> float:
        """Calculate behavioral similarity between two addresses."""
        p1 = self.address_profiles.get(addr1)
        p2 = self.address_profiles.get(addr2)

        if not p1 or not p2:
            return 0.0

        score = 0.0
        weights_total = 0.0

        # Value similarity
        if p1["avg_value"] > 0 and p2["avg_value"] > 0:
            ratio = min(p1["avg_value"], p2["avg_value"]) / max(p1["avg_value"], p2["avg_value"])
            score += ratio * 0.25
            weights_total += 0.25

        # Fee similarity
        if p1["avg_fee"] > 0 and p2["avg_fee"] > 0:
            ratio = min(p1["avg_fee"], p2["avg_fee"]) / max(p1["avg_fee"], p2["avg_fee"])
            score += ratio * 0.20
            weights_total += 0.20

        # Timing similarity
        if p1["preferred_hour"] >= 0 and p2["preferred_hour"] >= 0:
            hour_diff = abs(p1["preferred_hour"] - p2["preferred_hour"])
            hour_sim = 1.0 - min(hour_diff, 24 - hour_diff) / 12.0
            score += hour_sim * 0.25
            weights_total += 0.25

        # I/O ratio similarity
        if p1["input_output_ratio"] > 0 and p2["input_output_ratio"] > 0:
            ratio = min(p1["input_output_ratio"], p2["input_output_ratio"]) / \
                    max(p1["input_output_ratio"], p2["input_output_ratio"])
            score += ratio * 0.15
            weights_total += 0.15

        # Round amount ratio similarity
        round_sim = 1.0 - abs(p1["round_amount_ratio"] - p2["round_amount_ratio"])
        score += round_sim * 0.15
        weights_total += 0.15

        return score / weights_total if weights_total > 0 else 0.0


class WalletClusterer(BaseAgent):
    """
    Agent for clustering wallets based on multiple analysis methods.
    Identifies groups of addresses likely controlled by same entity.
    """

    AGENT_NAME = "WalletClusterer"
    AGENT_VERSION = "1.0.0"
    AGENT_DESCRIPTION = "Entity clustering using co-spending, temporal, and behavioral analysis"

    def __init__(self, config: Optional[AgentConfig] = None, adapter: Optional[BlockchainAdapter] = None):
        super().__init__(config)
        self.adapter = adapter or MockBlockchainAdapter(
            network=self.config.blockchain.network
        )
        self.co_spending_analyzer = CoSpendingAnalyzer()
        self.temporal_analyzer = TemporalAnalyzer()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.clusters: List[WalletCluster] = []

    def validate_input(self, target: str) -> bool:
        """Validate that target is a valid address or set of addresses."""
        return bool(target and len(target) >= 10)

    def analyze(self, target: str, context: Dict[str, Any] = None) -> AnalysisResult:
        """Perform wallet clustering analysis on the target address."""
        context = context or {}
        result = AnalysisResult(
            analysis_id=f"cluster_{uuid.uuid4().hex[:12]}",
            target=target,
            analysis_type="wallet_clustering",
            network=self.config.blockchain.network,
        )

        # Fetch transactions for the target address
        txs_data = self.adapter.get_address_transactions(target, limit=100)
        transactions = [Transaction.from_dict(tx_data) for tx_data in txs_data]

        # Collect all related addresses
        related_addresses = set()
        for tx in transactions:
            related_addresses.update(tx.involved_addresses)

        self.update_metric("related_addresses", len(related_addresses))
        self.update_metric("transactions_analyzed", len(transactions))

        # Phase 1: Co-spending analysis
        co_spending_clusters = self._run_co_spending_analysis(transactions, result)

        # Phase 2: Temporal analysis
        temporal_clusters = self._run_temporal_analysis(transactions, related_addresses, result)

        # Phase 3: Behavioral analysis
        behavioral_clusters = self._run_behavioral_analysis(
            related_addresses, transactions, result
        )

        # Phase 4: Merge clusters
        merged_clusters = self._merge_clusters(
            co_spending_clusters, temporal_clusters, behavioral_clusters
        )

        # Create WalletCluster objects
        for i, cluster_addrs in enumerate(merged_clusters):
            cluster = WalletCluster(
                cluster_id=f"cluster_{uuid.uuid4().hex[:8]}",
                label=f"Cluster {i + 1}",
                creation_method="multi_heuristic",
            )
            for addr in cluster_addrs:
                wallet = Wallet(
                    wallet_id=f"wallet_{hashlib.md5(addr.encode()).hexdigest()[:12]}",
                    addresses=[addr],
                    network=self.config.blockchain.network,
                )
                cluster.add_wallet(wallet)

            if target in cluster_addrs:
                cluster.confidence = 0.85
                cluster.add_evidence(
                    "target_inclusion",
                    f"Target address {target[:16]}... found in cluster",
                    0.85,
                )

            self.clusters.append(cluster)
            result.agent_results.setdefault("clusters", []).append(cluster.to_dict())

        # Generate findings
        self._generate_clustering_findings(result)

        return result

    def _run_co_spending_analysis(self, transactions: List[Transaction],
                                   result: AnalysisResult) -> List[Set[str]]:
        """Run co-spending analysis on transactions."""
        co_spending_clusters = self.co_spending_analyzer.analyze_transactions(transactions)
        self.update_metric("co_spending_clusters", len(co_spending_clusters))

        if co_spending_clusters:
            result.agent_results["co_spending"] = {
                "clusters_found": len(co_spending_clusters),
                "total_addresses": sum(len(c) for c in co_spending_clusters),
                "avg_cluster_size": sum(len(c) for c in co_spending_clusters) / len(co_spending_clusters),
            }

        return co_spending_clusters

    def _run_temporal_analysis(self, transactions: List[Transaction],
                                addresses: Set[str],
                                result: AnalysisResult) -> List[Set[str]]:
        """Run temporal correlation analysis."""
        for tx in transactions:
            self.temporal_analyzer.add_transaction(tx)

        address_list = list(addresses)[:100]  # Limit for performance
        temporal_clusters = self.temporal_analyzer.find_temporal_clusters(
            address_list,
            threshold=self.config.clustering.min_similarity_score
        )
        self.update_metric("temporal_clusters", len(temporal_clusters))

        if temporal_clusters:
            result.agent_results["temporal"] = {
                "clusters_found": len(temporal_clusters),
                "total_addresses": sum(len(c) for c in temporal_clusters),
            }

        return temporal_clusters

    def _run_behavioral_analysis(self, addresses: Set[str],
                                  transactions: List[Transaction],
                                  result: AnalysisResult) -> List[Set[str]]:
        """Run behavioral similarity analysis."""
        # Build profiles for each address
        addr_tx_map: Dict[str, List[Transaction]] = defaultdict(list)
        for tx in transactions:
            for addr in tx.involved_addresses:
                if addr in addresses:
                    addr_tx_map[addr].append(tx)

        for addr, txs in addr_tx_map.items():
            self.behavioral_analyzer.build_profile(addr, txs)

        # Find similar addresses
        behavioral_clusters = []
        addr_list = list(addresses)[:50]  # Limit for performance
        visited = set()

        for i, addr1 in enumerate(addr_list):
            if addr1 in visited:
                continue
            cluster = {addr1}
            for addr2 in addr_list[i + 1:]:
                if addr2 in visited:
                    continue
                similarity = self.behavioral_analyzer.calculate_similarity(addr1, addr2)
                if similarity >= 0.7:
                    cluster.add(addr2)
                    visited.add(addr2)
            if len(cluster) >= 2:
                behavioral_clusters.append(cluster)
            visited.add(addr1)

        self.update_metric("behavioral_clusters", len(behavioral_clusters))
        return behavioral_clusters

    def _merge_clusters(self, *cluster_sets: List[Set[str]]) -> List[Set[str]]:
        """Merge overlapping clusters from different methods."""
        all_addresses = set()
        for clusters in cluster_sets:
            for cluster in clusters:
                all_addresses.update(cluster)

        # Build adjacency from cluster memberships
        adjacency: Dict[str, Set[str]] = defaultdict(set)
        for clusters in cluster_sets:
            for cluster in clusters:
                cluster_list = list(cluster)
                for i in range(len(cluster_list)):
                    for j in range(i + 1, len(cluster_list)):
                        adjacency[cluster_list[i]].add(cluster_list[j])
                        adjacency[cluster_list[j]].add(cluster_list[i])

        # Find connected components
        visited = set()
        merged = []

        for address in adjacency:
            if address in visited:
                continue
            component = set()
            stack = [address]
            while stack:
                current = stack.pop()
                if current in visited:
                    continue
                visited.add(current)
                component.add(current)
                for neighbor in adjacency[current]:
                    if neighbor not in visited:
                        stack.append(neighbor)
            if len(component) >= 2:
                merged.append(component)

        return merged

    def _generate_clustering_findings(self, result: AnalysisResult) -> None:
        """Generate findings from clustering analysis."""
        large_clusters = [c for c in self.clusters if c.size >= 5]
        for cluster in large_clusters:
            finding = self.create_finding(
                title=f"Large wallet cluster identified ({cluster.size} addresses)",
                description=f"A cluster of {cluster.size} addresses with {cluster.num_addresses} total "
                           f"addresses was identified using {cluster.creation_method}.",
                severity=SeverityLevel.MEDIUM,
                category=RiskCategory.UNUSUAL_ACTIVITY,
                confidence=cluster.confidence,
                recommendation="Investigate the entity controlling this cluster for compliance purposes.",
                affected_addresses=list(cluster.addresses)[:10],
            )
            result.add_finding(finding)

        if len(self.clusters) > 10:
            finding = self.create_finding(
                title="Extensive clustering detected",
                description=f"{len(self.clusters)} distinct wallet clusters identified, suggesting "
                           f"complex multi-entity fund flows.",
                severity=SeverityLevel.HIGH,
                category=RiskCategory.MONEY_LAUNDERING,
                confidence=0.6,
                recommendation="Perform detailed investigation of inter-cluster relationships.",
            )
            result.add_finding(finding)
