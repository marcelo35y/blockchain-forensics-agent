"""
Transaction data models for blockchain forensics.
Represents transactions across different blockchain networks with detailed metadata.
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum


class TransactionType(Enum):
    """Types of blockchain transactions."""
    STANDARD = "standard"
    COINBASE = "coinbase"
    CONTRACT_CREATION = "contract_creation"
    CONTRACT_CALL = "contract_call"
    INTERNAL = "internal"
    TOKEN_TRANSFER = "token_transfer"
    MULTI_SIG = "multi_sig"
    UNKNOWN = "unknown"


class ConfirmationStatus(Enum):
    """Transaction confirmation status."""
    UNCONFIRMED = "unconfirmed"
    CONFIRMED = "confirmed"
    DEEP_CONFIRMED = "deep_confirmed"
    REORGED = "reorged"


@dataclass
class TransactionInput:
    """Represents a transaction input (source of funds)."""
    address: str
    value: float
    prev_tx_hash: str = ""
    prev_tx_index: int = 0
    script_sig: str = ""
    witness: List[str] = field(default_factory=list)
    sequence: int = 0xFFFFFFFF

    @property
    def address_short(self) -> str:
        """Shortened address for display."""
        if len(self.address) > 16:
            return f"{self.address[:8]}...{self.address[-8:]}"
        return self.address

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "value": self.value,
            "prev_tx_hash": self.prev_tx_hash,
            "prev_tx_index": self.prev_tx_index,
            "sequence": self.sequence,
        }


@dataclass
class TransactionOutput:
    """Represents a transaction output (destination of funds)."""
    address: str
    value: float
    index: int = 0
    script_pubkey: str = ""
    spent: bool = False
    spent_by_tx: Optional[str] = None
    is_op_return: bool = False
    is_change: bool = False

    @property
    def address_short(self) -> str:
        """Shortened address for display."""
        if len(self.address) > 16:
            return f"{self.address[:8]}...{self.address[-8:]}"
        return self.address

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "value": self.value,
            "index": self.index,
            "spent": self.spent,
            "spent_by_tx": self.spent_by_tx,
            "is_change": self.is_change,
        }


@dataclass
class Transaction:
    """
    Complete blockchain transaction representation.
    Supports Bitcoin, Ethereum, and other UTXO/account-based chains.
    """
    tx_hash: str
    block_height: int = 0
    block_hash: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    network: str = "bitcoin"
    tx_type: TransactionType = TransactionType.STANDARD
    inputs: List[TransactionInput] = field(default_factory=list)
    outputs: List[TransactionOutput] = field(default_factory=list)
    fee: float = 0.0
    size: int = 0
    weight: int = 0
    confirmations: int = 0
    version: int = 2
    locktime: int = 0
    is_coinbase: bool = False
    hex_data: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def total_input_value(self) -> float:
        """Calculate total value of all inputs."""
        return sum(inp.value for inp in self.inputs)

    @property
    def total_output_value(self) -> float:
        """Calculate total value of all outputs."""
        return sum(out.value for out in self.outputs)

    @property
    def input_addresses(self) -> List[str]:
        """Get all unique input addresses."""
        return list(set(inp.address for inp in self.inputs))

    @property
    def output_addresses(self) -> List[str]:
        """Get all unique output addresses."""
        return list(set(out.address for out in self.outputs))

    @property
    def involved_addresses(self) -> List[str]:
        """Get all unique addresses involved in this transaction."""
        return list(set(self.input_addresses + self.output_addresses))

    @property
    def num_inputs(self) -> int:
        return len(self.inputs)

    @property
    def num_outputs(self) -> int:
        return len(self.outputs)

    @property
    def confirmation_status(self) -> ConfirmationStatus:
        if self.confirmations == 0:
            return ConfirmationStatus.UNCONFIRMED
        elif self.confirmations < 6:
            return ConfirmationStatus.CONFIRMED
        else:
            return ConfirmationStatus.DEEP_CONFIRMED

    def has_address(self, address: str) -> bool:
        """Check if address is involved in this transaction."""
        return address in self.involved_addresses

    def get_address_role(self, address: str) -> str:
        """Determine the role of an address in this transaction."""
        is_input = address in [inp.address for inp in self.inputs]
        is_output = address in [out.address for out in self.outputs]
        if is_input and is_output:
            return "both"
        elif is_input:
            return "sender"
        elif is_output:
            return "receiver"
        return "uninvolved"

    def calculate_fee_rate(self) -> float:
        """Calculate fee rate (fee per byte)."""
        if self.size > 0:
            return self.fee / self.size
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize transaction to dictionary."""
        return {
            "tx_hash": self.tx_hash,
            "block_height": self.block_height,
            "timestamp": self.timestamp.isoformat(),
            "network": self.network,
            "tx_type": self.tx_type.value,
            "inputs": [inp.to_dict() for inp in self.inputs],
            "outputs": [out.to_dict() for out in self.outputs],
            "fee": self.fee,
            "size": self.size,
            "confirmations": self.confirmations,
            "total_input_value": self.total_input_value,
            "total_output_value": self.total_output_value,
            "tags": self.tags,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Transaction":
        """Deserialize transaction from dictionary."""
        inputs = [TransactionInput(**inp) for inp in data.get("inputs", [])]
        outputs = [TransactionOutput(**out) for out in data.get("outputs", [])]
        return cls(
            tx_hash=data["tx_hash"],
            block_height=data.get("block_height", 0),
            timestamp=datetime.fromisoformat(data["timestamp"]) if "timestamp" in data else datetime.utcnow(),
            network=data.get("network", "bitcoin"),
            inputs=inputs,
            outputs=outputs,
            fee=data.get("fee", 0.0),
            size=data.get("size", 0),
            confirmations=data.get("confirmations", 0),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )

    def fingerprint(self) -> str:
        """Generate a unique fingerprint for this transaction."""
        data = f"{self.tx_hash}:{self.block_height}:{self.total_input_value}:{self.total_output_value}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
