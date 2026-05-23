"""
Graph engine for blockchain transaction analysis.
Provides graph-based analysis capabilities for tracing funds and identifying patterns.
"""

import hashlib
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional, Any, Callable
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    """Node in the transaction graph (represents an address)."""
    node_id: str
    address: str
    label: str = ""
    node_type: str = "address"
    total_in: float = 0.0
    total_out: float = 0.0
    tx_count: int = 0
    risk_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def balance(self) -> float:
        return self.total_in - self.total_out

    @property
    def turnover(self) -> float:
        return self.total_out / self.total_in if self.total_in > 0 else 0.0


@dataclass
class GraphEdge:
    """Edge in the transaction graph (represents a transaction between addresses)."""
    edge_id: str
    source: str
    target: str
    value: float
    tx_hash: str
    timestamp: Optional[datetime] = None
    fee: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class TransactionGraph:
    """
    Directed graph representation of blockchain transactions.
    Supports traversal, path finding, and pattern detection.
    """

    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: Dict[str, GraphEdge] = {}
        self.adjacency: Dict[str, Set[str]] = defaultdict(set)  # outgoing
        self.reverse_adjacency: Dict[str, Set[str]] = defaultdict(set)  # incoming
        self._edge_index: Dict[Tuple[str, str], List[str]] = defaultdict(list)

    def add_node(self, address: str, **kwargs) -> GraphNode:
        """Add a node (address) to the graph."""
        if address in self.nodes:
            node = self.nodes[address]
            for k, v in kwargs.items():
                if hasattr(node, k):
                    setattr(node, k, v)
            return node

        node = GraphNode(
            node_id=hashlib.md5(address.encode()).hexdigest()[:12],
            address=address,
            **kwargs
        )
        self.nodes[address] = node
        return node

    def add_edge(self, source: str, target: str, value: float, tx_hash: str,
                 timestamp: Optional[datetime] = None, **kwargs) -> GraphEdge:
        """Add an edge (transaction) between two nodes."""
        if source not in self.nodes:
            self.add_node(source)
        if target not in self.nodes:
            self.add_node(target)

        edge_id = f"{tx_hash}:{source[:8]}:{target[:8]}"
        edge = GraphEdge(
            edge_id=edge_id,
            source=source,
            target=target,
            value=value,
            tx_hash=tx_hash,
            timestamp=timestamp,
            **kwargs
        )

        self.edges[edge_id] = edge
        self.adjacency[source].add(target)
        self.reverse_adjacency[target].add(source)
        self._edge_index[(source, target)].append(edge_id)

        # Update node statistics
        self.nodes[source].total_out += value
        self.nodes[target].total_in += value
        self.nodes[source].tx_count += 1
        self.nodes[target].tx_count += 1

        return edge

    def get_outgoing_edges(self, address: str) -> List[GraphEdge]:
        """Get all outgoing edges from an address."""
        edges = []
        for target in self.adjacency.get(address, set()):
            for edge_id in self._edge_index.get((address, target), []):
                if edge_id in self.edges:
                    edges.append(self.edges[edge_id])
        return edges

    def get_incoming_edges(self, address: str) -> List[GraphEdge]:
        """Get all incoming edges to an address."""
        edges = []
        for source in self.reverse_adjacency.get(address, set()):
            for edge_id in self._edge_index.get((source, address), []):
                if edge_id in self.edges:
                    edges.append(self.edges[edge_id])
        return edges

    def get_neighbors(self, address: str, direction: str = "both") -> Set[str]:
        """Get neighboring addresses."""
        neighbors = set()
        if direction in ("out", "both"):
            neighbors.update(self.adjacency.get(address, set()))
        if direction in ("in", "both"):
            neighbors.update(self.reverse_adjacency.get(address, set()))
        return neighbors

    def find_paths(self, source: str, target: str, max_depth: int = 5,
                   max_paths: int = 100) -> List[List[str]]:
        """Find all paths between source and target up to max_depth."""
        if source not in self.nodes or target not in self.nodes:
            return []

        paths = []
        visited = set()

        def dfs(current: str, path: List[str], depth: int) -> None:
            if len(paths) >= max_paths:
                return
            if depth > max_depth:
                return
            if current == target:
                paths.append(list(path))
                return

            visited.add(current)
            for neighbor in self.adjacency.get(current, set()):
                if neighbor not in visited:
                    path.append(neighbor)
                    dfs(neighbor, path, depth + 1)
                    path.pop()
            visited.discard(current)

        dfs(source, [source], 0)
        return paths

    def bfs_trace(self, source: str, max_depth: int = 5) -> Dict[str, Dict[str, Any]]:
        """BFS-based fund tracing from a source address."""
        visited = {}
        queue = deque([(source, 0, 0.0)])

        while queue:
            address, depth, cumulative_value = queue.popleft()

            if address in visited or depth > max_depth:
                continue

            node = self.nodes.get(address)
            visited[address] = {
                "address": address,
                "depth": depth,
                "cumulative_value": cumulative_value,
                "in_degree": len(self.reverse_adjacency.get(address, set())),
                "out_degree": len(self.adjacency.get(address, set())),
                "risk_score": node.risk_score if node else 0.0,
            }

            for edge in self.get_outgoing_edges(address):
                if edge.target not in visited:
                    queue.append((edge.target, depth + 1, cumulative_value + edge.value))

        return visited

    def detect_cycles(self, address: str, max_depth: int = 5) -> List[List[str]]:
        """Detect cycles involving a specific address (round-tripping detection)."""
        cycles = []
        visited = set()
        path = []

        def dfs(current: str, depth: int) -> None:
            if depth > max_depth:
                return
            visited.add(current)
            path.append(current)

            for neighbor in self.adjacency.get(current, set()):
                if neighbor == address and len(path) > 2:
                    cycles.append(list(path) + [address])
                elif neighbor not in visited:
                    dfs(neighbor, depth + 1)

            path.pop()
            visited.discard(current)

        dfs(address, 0)
        return cycles

    def find_fan_out(self, address: str, threshold: int = 5) -> Dict[str, Any]:
        """Detect fan-out patterns (one-to-many distributions)."""
        outgoing = self.get_outgoing_edges(address)
        if len(outgoing) < threshold:
            return {"is_fan_out": False, "count": len(outgoing)}

        total_value = sum(e.value for e in outgoing)
        target_values = [(e.target, e.value) for e in outgoing]
        target_values.sort(key=lambda x: x[1])

        return {
            "is_fan_out": True,
            "source": address,
            "count": len(outgoing),
            "total_value": total_value,
            "avg_value": total_value / len(outgoing) if outgoing else 0,
            "targets": target_values,
            "is_uniform": self._check_uniform_distribution([v for _, v in target_values]),
        }

    def find_fan_in(self, address: str, threshold: int = 5) -> Dict[str, Any]:
        """Detect fan-in patterns (many-to-one consolidation)."""
        incoming = self.get_incoming_edges(address)
        if len(incoming) < threshold:
            return {"is_fan_in": False, "count": len(incoming)}

        total_value = sum(e.value for e in incoming)
        source_values = [(e.source, e.value) for e in incoming]

        return {
            "is_fan_in": True,
            "target": address,
            "count": len(incoming),
            "total_value": total_value,
            "avg_value": total_value / len(incoming) if incoming else 0,
            "sources": source_values,
        }

    def _check_uniform_distribution(self, values: List[float]) -> bool:
        """Check if values are approximately uniformly distributed."""
        if len(values) < 3:
            return False
        avg = sum(values) / len(values)
        if avg == 0:
            return False
        variance = sum((v - avg) ** 2 for v in values) / len(values)
        cv = (variance ** 0.5) / avg  # Coefficient of variation
        return cv < 0.1  # Less than 10% variation

    def get_subgraph(self, addresses: Set[str]) -> "TransactionGraph":
        """Extract a subgraph containing only the specified addresses."""
        subgraph = TransactionGraph()
        for addr in addresses:
            if addr in self.nodes:
                subgraph.add_node(addr, **self.nodes[addr].__dict__)

        for edge in self.edges.values():
            if edge.source in addresses and edge.target in addresses:
                subgraph.add_edge(edge.source, edge.target, edge.value,
                                  edge.tx_hash, edge.timestamp)
        return subgraph

    @property
    def num_nodes(self) -> int:
        return len(self.nodes)

    @property
    def num_edges(self) -> int:
        return len(self.edges)

    @property
    def total_value(self) -> float:
        return sum(e.value for e in self.edges.values())

    def statistics(self) -> Dict[str, Any]:
        """Get graph statistics."""
        in_degrees = [len(self.reverse_adjacency.get(n, set())) for n in self.nodes]
        out_degrees = [len(self.adjacency.get(n, set())) for n in self.nodes]

        return {
            "num_nodes": self.num_nodes,
            "num_edges": self.num_edges,
            "total_value": self.total_value,
            "avg_in_degree": sum(in_degrees) / len(in_degrees) if in_degrees else 0,
            "avg_out_degree": sum(out_degrees) / len(out_degrees) if out_degrees else 0,
            "max_in_degree": max(in_degrees) if in_degrees else 0,
            "max_out_degree": max(out_degrees) if out_degrees else 0,
            "isolated_nodes": sum(1 for n in self.nodes
                                  if len(self.adjacency.get(n, set())) == 0
                                  and len(self.reverse_adjacency.get(n, set())) == 0),
        }
