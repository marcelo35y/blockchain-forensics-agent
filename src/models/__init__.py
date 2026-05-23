"""
Data models for Blockchain Forensics Agent.
Defines core data structures for transactions, wallets, clusters, and analysis results.
"""

from .transaction import Transaction, TransactionInput, TransactionOutput
from .wallet import Wallet, WalletCluster, AddressType
from .analysis import (
    AnalysisResult,
    Finding,
    RiskScore,
    PatternMatch,
    ComplianceResult,
    TracingResult,
    SeverityLevel,
)

__all__ = [
    "Transaction", "TransactionInput", "TransactionOutput",
    "Wallet", "WalletCluster", "AddressType",
    "AnalysisResult", "Finding", "RiskScore", "PatternMatch",
    "ComplianceResult", "TracingResult", "SeverityLevel",
]
