"""
AnomalyDetector Agent — Statistical anomaly detection for blockchain transactions.

Implements multiple detection methods:
- Z-score based outlier detection
- IQR (Interquartile Range) analysis
- Isolation Forest (simplified)
- Temporal anomaly detection (unusual timing)
- Velocity anomaly detection (unusual transaction frequency)
- Amount distribution analysis
"""

import uuid
import math
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
import statistics

from src.agents.base_agent import BaseAgent
from src.models.transaction import Transaction
from src.models.analysis import AnalysisResult, Finding, RiskScore, SeverityLevel, RiskCategory
from src.utils.blockchain_adapter import MockBlockchainAdapter, BlockchainAdapter
from src.config import AgentConfig


logger = logging.getLogger(__name__)


class ZScoreDetector:
    """Z-score based anomaly detection for transaction amounts."""

    def __init__(self, threshold: float = 3.0):
        self.threshold = threshold
        self.mean: float = 0.0
        self.std: float = 0.0

    def fit(self, values: List[float]) -> None:
        """Calculate mean and standard deviation from data."""
        if len(values) < 2:
            self.mean = sum(values) / len(values) if values else 0
            self.std = 0.0
            return
        self.mean = sum(values) / len(values)
        variance = sum((v - self.mean) ** 2 for v in values) / (len(values) - 1)
        self.std = math.sqrt(variance) if variance > 0 else 0.0

    def detect(self, values: List[float]) -> List[Tuple[int, float, float]]:
        """
        Detect anomalies using Z-score.
        Returns list of (index, value, z_score) for anomalous values.
        """
        if self.std == 0:
            return []

        anomalies = []
        for i, v in enumerate(values):
            z_score = abs(v - self.mean) / self.std
            if z_score > self.threshold:
                anomalies.append((i, v, z_score))
        return anomalies

    def score(self, value: float) -> float:
        """Calculate Z-score for a single value."""
        if self.std == 0:
            return 0.0
        return abs(value - self.mean) / self.std


class IQRDetector:
    """Interquartile Range based anomaly detection."""

    def __init__(self, multiplier: float = 1.5):
        self.multiplier = multiplier
        self.q1: float = 0.0
        self.q3: float = 0.0
        self.iqr: float = 0.0
        self.lower_bound: float = 0.0
        self.upper_bound: float = 0.0

    def fit(self, values: List[float]) -> None:
        """Calculate IQR bounds from data."""
        if len(values) < 4:
            sorted_vals = sorted(values)
            self.q1 = sorted_vals[0] if sorted_vals else 0
            self.q3 = sorted_vals[-1] if sorted_vals else 0
        else:
            sorted_vals = sorted(values)
            n = len(sorted_vals)
            q1_idx = n // 4
            q3_idx = 3 * n // 4
            self.q1 = sorted_vals[q1_idx]
            self.q3 = sorted_vals[q3_idx]

        self.iqr = self.q3 - self.q1
        self.lower_bound = self.q1 - self.multiplier * self.iqr
        self.upper_bound = self.q3 + self.multiplier * self.iqr

    def detect(self, values: List[float]) -> List[Tuple[int, float, str]]:
        """
        Detect anomalies using IQR.
        Returns list of (index, value, direction) for anomalous values.
        """
        anomalies = []
        for i, v in enumerate(values):
            if v < self.lower_bound:
                anomalies.append((i, v, "low"))
            elif v > self.upper_bound:
                anomalies.append((i, v, "high"))
        return anomalies


class IsolationForestSimple:
    """
    Simplified Isolation Forest for anomaly detection.
    Uses random partitioning to isolate anomalies.
    """

    def __init__(self, n_trees: int = 100, sample_size: int = 256, contamination: float = 0.05):
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.contamination = contamination
        self.trees: List[Dict[str, Any]] = []
        self.threshold: float = 0.0

    def fit(self, data: List[List[float]]) -> None:
        """Build isolation trees."""
        import random
        n_features = len(data[0]) if data else 0
        sample_sz = min(self.sample_size, len(data))

        for _ in range(self.n_trees):
            sample_indices = random.sample(range(len(data)), sample_sz)
            sample = [data[i] for i in sample_indices]
            tree = self._build_tree(sample, 0, int(math.log2(sample_sz)) + 1, n_features)
            self.trees.append(tree)

        # Calculate anomaly scores for training data
        scores = [self._anomaly_score(point) for point in data]
        scores.sort()
        threshold_idx = int(len(scores) * (1 - self.contamination))
        self.threshold = scores[min(threshold_idx, len(scores) - 1)]

    def _build_tree(self, data: List[List[float]], depth: int,
                    max_depth: int, n_features: int) -> Dict[str, Any]:
        """Build a single isolation tree."""
        import random

        if depth >= max_depth or len(data) <= 1:
            return {"type": "leaf", "size": len(data), "depth": depth}

        feature = random.randint(0, n_features - 1)
        values = [row[feature] for row in data]
        min_val = min(values)
        max_val = max(values)

        if min_val == max_val:
            return {"type": "leaf", "size": len(data), "depth": depth}

        split_value = random.uniform(min_val, max_val)
        left = [row for row in data if row[feature] < split_value]
        right = [row for row in data if row[feature] >= split_value]

        return {
            "type": "internal",
            "feature": feature,
            "split": split_value,
            "left": self._build_tree(left, depth + 1, max_depth, n_features),
            "right": self._build_tree(right, depth + 1, max_depth, n_features),
        }

    def _path_length(self, point: List[float], tree: Dict[str, Any]) -> float:
        """Calculate path length of a point in a tree."""
        if tree["type"] == "leaf":
            size = tree["size"]
            # Average path length of unsuccessful search in BST
            if size <= 1:
                return tree["depth"]
            return tree["depth"] + 2.0 * (math.log(size - 1) + 0.5772156649) - 2.0 * (size - 1) / size

        if point[tree["feature"]] < tree["split"]:
            return self._path_length(point, tree["left"])
        return self._path_length(point, tree["right"])

    def _anomaly_score(self, point: List[float]) -> float:
        """Calculate anomaly score for a point."""
        if not self.trees:
            return 0.0
        avg_path = sum(self._path_length(point, tree) for tree in self.trees) / len(self.trees)
        c_n = 2.0 * (math.log(self.sample_size - 1) + 0.5772156649) - 2.0 * (self.sample_size - 1) / self.sample_size
        return 2.0 ** (-avg_path / c_n) if c_n > 0 else 0.0

    def predict(self, point: List[float]) -> bool:
        """Predict if a point is an anomaly."""
        return self._anomaly_score(point) >= self.threshold

    def score(self, point: List[float]) -> float:
        """Get anomaly score for a point."""
        return self._anomaly_score(point)


class VelocityDetector:
    """Detects anomalous transaction velocity (frequency changes)."""

    def __init__(self, window_hours: int = 24, threshold_multiplier: float = 2.0):
        self.window_hours = window_hours
        self.threshold_multiplier = threshold_multiplier

    def detect_velocity_anomalies(self, timestamps: List[datetime]) -> List[Dict[str, Any]]:
        """Detect periods of unusual transaction frequency."""
        if len(timestamps) < 3:
            return []

        sorted_ts = sorted(timestamps)
        anomalies = []

        # Calculate transactions per window
        window_counts = []
        window_start = sorted_ts[0]
        window_delta = timedelta(hours=self.window_hours)

        current_count = 0
        for ts in sorted_ts:
            if ts - window_start > window_delta:
                window_counts.append(current_count)
                window_start = ts
                current_count = 1
            else:
                current_count += 1
        window_counts.append(current_count)

        if len(window_counts) < 2:
            return []

        # Calculate thresholds
        avg_count = sum(window_counts) / len(window_counts)
        std_count = math.sqrt(sum((c - avg_count) ** 2 for c in window_counts) / len(window_counts))
        threshold = avg_count + self.threshold_multiplier * std_count

        # Find anomalous windows
        for i, count in enumerate(window_counts):
            if count > threshold:
                anomalies.append({
                    "window_index": i,
                    "count": count,
                    "expected": avg_count,
                    "threshold": threshold,
                    "severity": "high" if count > 2 * threshold else "medium",
                })

        return anomalies


class AnomalyDetector(BaseAgent):
    """
    Agent for detecting anomalous patterns in blockchain transactions.
    Uses multiple statistical and ML-based detection methods.
    """

    AGENT_NAME = "AnomalyDetector"
    AGENT_VERSION = "1.0.0"
    AGENT_DESCRIPTION = "Statistical anomaly detection using Z-score, IQR, and ML methods"

    def __init__(self, config: Optional[AgentConfig] = None, adapter: Optional[BlockchainAdapter] = None):
        super().__init__(config)
        self.adapter = adapter or MockBlockchainAdapter(
            network=self.config.blockchain.network
        )
        self.zscore_detector = ZScoreDetector(threshold=self.config.anomaly.zscore_threshold)
        self.iqr_detector = IQRDetector(multiplier=self.config.anomaly.iqr_multiplier)
        self.velocity_detector = VelocityDetector(
            window_hours=self.config.anomaly.temporal_window_hours
        )
        self.isolation_forest = None

    def validate_input(self, target: str) -> bool:
        """Validate target is a valid address."""
        return bool(target and len(target) >= 10)

    def analyze(self, target: str, context: Dict[str, Any] = None) -> AnalysisResult:
        """Perform anomaly detection analysis on the target address."""
        context = context or {}
        result = AnalysisResult(
            analysis_id=f"anomaly_{uuid.uuid4().hex[:12]}",
            target=target,
            analysis_type="anomaly_detection",
            network=self.config.blockchain.network,
        )

        # Fetch transactions
        txs_data = self.adapter.get_address_transactions(target, limit=200)
        transactions = [Transaction.from_dict(tx_data) for tx_data in txs_data]

        if not transactions:
            result.status = "completed"
            result.risk_score.confidence = 0.1
            return result

        # Extract features
        amounts = self._extract_amounts(transactions, target)
        timestamps = [tx.timestamp for tx in transactions]
        fees = [tx.fee for tx in transactions]
        input_counts = [tx.num_inputs for tx in transactions]
        output_counts = [tx.num_outputs for tx in transactions]

        # Method 1: Z-score on amounts
        amount_anomalies = self._detect_zscore_anomalies(amounts, result)

        # Method 2: IQR on amounts
        iqr_anomalies = self._detect_iqr_anomalies(amounts, result)

        # Method 3: Velocity anomalies
        velocity_anomalies = self._detect_velocity_anomalies(timestamps, result)

        # Method 4: Fee anomalies
        fee_anomalies = self._detect_fee_anomalies(fees, result)

        # Method 5: Structural anomalies (unusual input/output patterns)
        structural_anomalies = self._detect_structural_anomalies(
            input_counts, output_counts, result
        )

        # Method 6: ML-based detection (Isolation Forest)
        ml_anomalies = self._detect_ml_anomalies(
            amounts, fees, input_counts, output_counts, timestamps, result
        )

        # Calculate risk score
        self._calculate_risk_score(
            result, amount_anomalies, iqr_anomalies,
            velocity_anomalies, fee_anomalies, structural_anomalies, ml_anomalies
        )

        return result

    def _extract_amounts(self, transactions: List[Transaction], address: str) -> List[float]:
        """Extract transaction amounts relevant to the target address."""
        amounts = []
        for tx in transactions:
            # Get amounts where target address is involved
            for out in tx.outputs:
                if out.address == address:
                    amounts.append(out.value)
            for inp in tx.inputs:
                if inp.address == address:
                    amounts.append(inp.value)
        return amounts if amounts else [0.0]

    def _detect_zscore_anomalies(self, amounts: List[float],
                                  result: AnalysisResult) -> int:
        """Detect anomalies using Z-score method."""
        self.zscore_detector.fit(amounts)
        anomalies = self.zscore_detector.detect(amounts)

        for idx, value, z_score in anomalies:
            finding = self.create_finding(
                title=f"Z-score anomaly: unusual transaction amount",
                description=f"Transaction amount {value:.8f} has Z-score {z_score:.2f} "
                           f"(threshold: {self.zscore_detector.threshold})",
                severity=SeverityLevel.HIGH if z_score > 5 else SeverityLevel.MEDIUM,
                category=RiskCategory.UNUSUAL_ACTIVITY,
                confidence=min(0.95, z_score / 10.0),
                recommendation="Investigate the source and purpose of this unusual transaction amount.",
            )
            result.add_finding(finding)

        result.agent_results["zscore"] = {
            "mean": self.zscore_detector.mean,
            "std": self.zscore_detector.std,
            "anomalies_found": len(anomalies),
            "threshold": self.zscore_detector.threshold,
        }
        return len(anomalies)

    def _detect_iqr_anomalies(self, amounts: List[float],
                               result: AnalysisResult) -> int:
        """Detect anomalies using IQR method."""
        self.iqr_detector.fit(amounts)
        anomalies = self.iqr_detector.detect(amounts)

        for idx, value, direction in anomalies:
            finding = self.create_finding(
                title=f"IQR anomaly: {'extremely high' if direction == 'high' else 'extremely low'} amount",
                description=f"Amount {value:.8f} is {'above' if direction == 'high' else 'below'} "
                           f"IQR bounds [{self.iqr_detector.lower_bound:.8f}, "
                           f"{self.iqr_detector.upper_bound:.8f}]",
                severity=SeverityLevel.MEDIUM,
                category=RiskCategory.UNUSUAL_ACTIVITY,
                confidence=0.7,
            )
            result.add_finding(finding)

        result.agent_results["iqr"] = {
            "q1": self.iqr_detector.q1,
            "q3": self.iqr_detector.q3,
            "iqr": self.iqr_detector.iqr,
            "lower_bound": self.iqr_detector.lower_bound,
            "upper_bound": self.iqr_detector.upper_bound,
            "anomalies_found": len(anomalies),
        }
        return len(anomalies)

    def _detect_velocity_anomalies(self, timestamps: List[datetime],
                                    result: AnalysisResult) -> int:
        """Detect transaction velocity anomalies."""
        anomalies = self.velocity_detector.detect_velocity_anomalies(timestamps)

        for anomaly in anomalies:
            finding = self.create_finding(
                title="Transaction velocity anomaly",
                description=f"Unusual spike of {anomaly['count']} transactions in "
                           f"{self.velocity_detector.window_hours}h window "
                           f"(expected: {anomaly['expected']:.1f})",
                severity=SeverityLevel.HIGH if anomaly["severity"] == "high" else SeverityLevel.MEDIUM,
                category=RiskCategory.UNUSUAL_ACTIVITY,
                confidence=0.75,
                recommendation="Investigate if this velocity spike indicates automated or suspicious activity.",
            )
            result.add_finding(finding)

        result.agent_results["velocity"] = {
            "window_hours": self.velocity_detector.window_hours,
            "anomalies_found": len(anomalies),
        }
        return len(anomalies)

    def _detect_fee_anomalies(self, fees: List[float],
                               result: AnalysisResult) -> int:
        """Detect unusual fee patterns."""
        if not fees:
            return 0

        avg_fee = sum(fees) / len(fees)
        anomalies = 0

        for fee in fees:
            if fee > avg_fee * 10:
                anomalies += 1
                finding = self.create_finding(
                    title="Abnormally high transaction fee",
                    description=f"Fee {fee:.8f} is {fee / avg_fee:.1f}x the average fee ({avg_fee:.8f})",
                    severity=SeverityLevel.LOW,
                    category=RiskCategory.UNUSUAL_ACTIVITY,
                    confidence=0.6,
                )
                result.add_finding(finding)

        result.agent_results["fee_analysis"] = {
            "avg_fee": avg_fee,
            "max_fee": max(fees),
            "high_fee_anomalies": anomalies,
        }
        return anomalies

    def _detect_structural_anomalies(self, input_counts: List[int],
                                      output_counts: List[int],
                                      result: AnalysisResult) -> int:
        """Detect structural anomalies in transaction shapes."""
        anomalies = 0

        # Transactions with many inputs (consolidation)
        if input_counts:
            avg_inputs = sum(input_counts) / len(input_counts)
            for count in input_counts:
                if count > avg_inputs * 3 and count > 10:
                    anomalies += 1
                    finding = self.create_finding(
                        title="High input consolidation transaction",
                        description=f"Transaction with {count} inputs "
                                   f"(average: {avg_inputs:.1f})",
                        severity=SeverityLevel.MEDIUM,
                        category=RiskCategory.MONEY_LAUNDERING,
                        confidence=0.5,
                        recommendation="Investigate if consolidation is part of a mixing pattern.",
                    )
                    result.add_finding(finding)

        # Transactions with many outputs (fan-out)
        if output_counts:
            avg_outputs = sum(output_counts) / len(output_counts)
            for count in output_counts:
                if count > avg_outputs * 3 and count > 10:
                    anomalies += 1
                    finding = self.create_finding(
                        title="High fan-out transaction",
                        description=f"Transaction with {count} outputs "
                                   f"(average: {avg_outputs:.1f})",
                        severity=SeverityLevel.MEDIUM,
                        category=RiskCategory.STRUCTURING,
                        confidence=0.5,
                        recommendation="Investigate if fan-out pattern indicates structuring.",
                    )
                    result.add_finding(finding)

        result.agent_results["structural"] = {
            "avg_inputs": sum(input_counts) / len(input_counts) if input_counts else 0,
            "avg_outputs": sum(output_counts) / len(output_counts) if output_counts else 0,
            "structural_anomalies": anomalies,
        }
        return anomalies

    def _detect_ml_anomalies(self, amounts: List[float], fees: List[float],
                              input_counts: List[int], output_counts: List[int],
                              timestamps: List[datetime],
                              result: AnalysisResult) -> int:
        """Detect anomalies using simplified Isolation Forest."""
        if not self.config.anomaly.enable_ml_detection:
            return 0

        # Build feature vectors
        features = []
        for i in range(len(amounts)):
            amount = amounts[i] if i < len(amounts) else 0
            fee = fees[i] if i < len(fees) else 0
            in_count = input_counts[i] if i < len(input_counts) else 0
            out_count = output_counts[i] if i < len(output_counts) else 0
            hour = timestamps[i].hour if i < len(timestamps) else 0
            features.append([amount, fee, in_count, out_count, hour])

        if len(features) < 10:
            return 0

        # Normalize features
        n_features = len(features[0])
        for j in range(n_features):
            col = [f[j] for f in features]
            col_min = min(col)
            col_max = max(col)
            col_range = col_max - col_min if col_max != col_min else 1
            for i in range(len(features)):
                features[i][j] = (features[i][j] - col_min) / col_range

        # Fit Isolation Forest
        self.isolation_forest = IsolationForestSimple(
            contamination=self.config.anomaly.contamination_factor
        )
        self.isolation_forest.fit(features)

        # Detect anomalies
        anomalies = 0
        for i, feat in enumerate(features):
            if self.isolation_forest.predict(feat):
                anomalies += 1

        if anomalies > 0:
            finding = self.create_finding(
                title=f"ML-detected anomalies: {anomalies} unusual transactions",
                description=f"Isolation Forest detected {anomalies} anomalous transactions "
                           f"out of {len(features)} analyzed.",
                severity=SeverityLevel.HIGH if anomalies > len(features) * 0.1 else SeverityLevel.MEDIUM,
                category=RiskCategory.UNUSUAL_ACTIVITY,
                confidence=0.8,
                recommendation="Review ML-flagged transactions for potential suspicious activity.",
            )
            result.add_finding(finding)

        result.agent_results["ml_detection"] = {
            "method": "isolation_forest",
            "features_analyzed": len(features),
            "anomalies_detected": anomalies,
            "contamination": self.config.anomaly.contamination_factor,
        }
        return anomalies

    def _calculate_risk_score(self, result: AnalysisResult, *anomaly_counts: int) -> None:
        """Calculate overall risk score from anomaly detection."""
        risk = result.risk_score
        total_anomalies = sum(anomaly_counts)

        risk.add_factor(
            "total_anomalies",
            min(100, total_anomalies * 10),
            0.4,
            f"{total_anomalies} total anomalies detected across all methods"
        )

        if total_anomalies > 5:
            risk.add_factor(
                "anomaly_density",
                min(100, total_anomalies * 5),
                0.3,
                "High anomaly density suggests systematic suspicious activity"
            )

        risk.add_factor(
            "detection_confidence",
            70.0,
            0.3,
            "Multiple detection methods provide cross-validation"
        )

        risk.confidence = 0.75
