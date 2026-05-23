"""
Wallet and clustering data models for blockchain forensics.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Any
from enum import Enum


class AddressType(Enum):
    """Types of blockchain addresses."""
    P2PKH = "p2pkh"          # Legacy Bitcoin (1...)
    P2SH = "p2sh"            # Script hash (3...)
    P2WPKH = "p2wpkh"        # Native segwit (bc1...)
    P2WSH = "p2wsh"          # Witness script hash
    P2TR = "p2tr"            # Taproot (bc1p...)
    ETH_EOA = "eth_eoa"      # Ethereum externally owned
    ETH_CONTRACT = "eth_contract"  # Ethereum contract
    EXCHANGE = "exchange"     # Known exchange address
    MIXER = "mixer"           # Known mixer/tumbler
    DARKNET = "darknet"       # Known darknet market
    RANSOMWARE = "ransomware" # Known ransomware
    STOLEN_FUNDS = "stolen"   # Known stolen funds
    SANCTIONS = "sanctions"   # OFAC sanctioned
    UNKNOWN = "unknown"


class WalletType(Enum):
    """Classification of wallet types."""
    INDIVIDUAL = "individual"
    EXCHANGE = "exchange"
    MIXER = "mixer"
    SERVICE = "service"
    DARKNET_MARKET = "darknet_market"
    GAMBLING = "gambling"
    RANSOMWARE = "ransomware"
    DEFI = "defi"
    BRIDGE = "bridge"
    GOVERNANCE = "governance"
    CUSTODIAL = "custodial"
    MULTI_SIG = "multi_sig"
    UNKNOWN = "unknown"


@dataclass
class Wallet:
    """
    Represents a blockchain wallet entity.
    A wallet can contain multiple addresses and track transaction history.
    """
    wallet_id: str
    addresses: List[str] = field(default_factory=list)
    wallet_type: WalletType = WalletType.UNKNOWN
    label: str = ""
    tags: List[str] = field(default_factory=list)
    network: str = "bitcoin"
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    total_received: float = 0.0
    total_sent: float = 0.0
    balance: float = 0.0
    transaction_count: int = 0
    risk_score: float = 0.0
    confidence: float = 0.0
    related_wallets: List[str] = field(default_factory=list)
    entity_name: str = ""
    jurisdiction: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    address_types: Dict[str, AddressType] = field(default_factory=dict)

    @property
    def primary_address(self) -> str:
        """Get the primary (first) address of the wallet."""
        return self.addresses[0] if self.addresses else ""

    @property
    def num_addresses(self) -> int:
        return len(self.addresses)

    @property
    def net_flow(self) -> float:
        """Calculate net flow (received - sent)."""
        return self.total_received - self.total_sent

    @property
    def turnover_ratio(self) -> float:
        """Calculate turnover ratio."""
        if self.total_received == 0:
            return 0.0
        return self.total_sent / self.total_received

    def has_address(self, address: str) -> bool:
        return address in self.addresses

    def add_address(self, address: str, addr_type: AddressType = AddressType.UNKNOWN) -> None:
        if address not in self.addresses:
            self.addresses.append(address)
            self.address_types[address] = addr_type

    def add_tag(self, tag: str) -> None:
        if tag not in self.tags:
            self.tags.append(tag)

    def update_activity(self, timestamp: datetime, amount_in: float = 0, amount_out: float = 0) -> None:
        """Update wallet activity metrics."""
        self.total_received += amount_in
        self.total_sent += amount_out
        self.balance += amount_in - amount_out
        self.transaction_count += 1
        if self.first_seen is None or timestamp < self.first_seen:
            self.first_seen = timestamp
        if self.last_seen is None or timestamp > self.last_seen:
            self.last_seen = timestamp

    def to_dict(self) -> Dict[str, Any]:
        return {
            "wallet_id": self.wallet_id,
            "addresses": self.addresses,
            "wallet_type": self.wallet_type.value,
            "label": self.label,
            "tags": self.tags,
            "network": self.network,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "total_received": self.total_received,
            "total_sent": self.total_sent,
            "balance": self.balance,
            "transaction_count": self.transaction_count,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "entity_name": self.entity_name,
            "jurisdiction": self.jurisdiction,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Wallet":
        first_seen = datetime.fromisoformat(data["first_seen"]) if data.get("first_seen") else None
        last_seen = datetime.fromisoformat(data["last_seen"]) if data.get("last_seen") else None
        return cls(
            wallet_id=data["wallet_id"],
            addresses=data.get("addresses", []),
            wallet_type=WalletType(data.get("wallet_type", "unknown")),
            label=data.get("label", ""),
            tags=data.get("tags", []),
            network=data.get("network", "bitcoin"),
            first_seen=first_seen,
            last_seen=last_seen,
            total_received=data.get("total_received", 0.0),
            total_sent=data.get("total_sent", 0.0),
            balance=data.get("balance", 0.0),
            transaction_count=data.get("transaction_count", 0),
            risk_score=data.get("risk_score", 0.0),
            confidence=data.get("confidence", 0.0),
            entity_name=data.get("entity_name", ""),
            jurisdiction=data.get("jurisdiction", ""),
        )


@dataclass
class WalletCluster:
    """
    A cluster of wallets believed to be controlled by the same entity.
    Implements clustering algorithms for blockchain analysis.
    """
    cluster_id: str
    wallets: List[Wallet] = field(default_factory=list)
    addresses: Set[str] = field(default_factory=set)
    label: str = ""
    cluster_type: WalletType = WalletType.UNKNOWN
    confidence: float = 0.0
    total_value: float = 0.0
    total_transactions: int = 0
    risk_score: float = 0.0
    entity_name: str = ""
    tags: List[str] = field(default_factory=list)
    creation_method: str = ""  # co-spending, temporal, behavioral, etc.
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return len(self.wallets)

    @property
    def num_addresses(self) -> int:
        return len(self.addresses)

    def add_wallet(self, wallet: Wallet) -> None:
        """Add a wallet to this cluster."""
        existing_ids = {w.wallet_id for w in self.wallets}
        if wallet.wallet_id not in existing_ids:
            self.wallets.append(wallet)
            self.addresses.update(wallet.addresses)
            self.total_value += wallet.balance
            self.total_transactions += wallet.transaction_count

    def merge(self, other: "WalletCluster") -> None:
        """Merge another cluster into this one."""
        existing_ids = {w.wallet_id for w in self.wallets}
        for wallet in other.wallets:
            if wallet.wallet_id not in existing_ids:
                self.wallets.append(wallet)
                existing_ids.add(wallet.wallet_id)
        self.addresses.update(other.addresses)
        self.total_value += other.total_value
        self.total_transactions += other.total_transactions
        self.evidence.extend(other.evidence)

    def contains_address(self, address: str) -> bool:
        return address in self.addresses

    def add_evidence(self, evidence_type: str, description: str, confidence: float, data: Any = None) -> None:
        self.evidence.append({
            "type": evidence_type,
            "description": description,
            "confidence": confidence,
            "data": data,
            "timestamp": datetime.utcnow().isoformat(),
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "wallet_count": self.size,
            "address_count": self.num_addresses,
            "label": self.label,
            "cluster_type": self.cluster_type.value,
            "confidence": self.confidence,
            "total_value": self.total_value,
            "total_transactions": self.total_transactions,
            "risk_score": self.risk_score,
            "entity_name": self.entity_name,
            "tags": self.tags,
            "creation_method": self.creation_method,
            "evidence_count": len(self.evidence),
        }
