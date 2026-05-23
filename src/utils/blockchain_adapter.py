"""
Blockchain adapter utilities for connecting to various blockchain APIs.
Provides unified interface for querying transactions, addresses, and blocks.
"""

import hashlib
import json
import time
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class BlockInfo:
    """Block metadata."""
    height: int
    hash: str
    timestamp: datetime
    tx_count: int
    size: int
    previous_hash: str = ""
    merkle_root: str = ""
    difficulty: float = 0.0


@dataclass
class AddressInfo:
    """Address metadata and statistics."""
    address: str
    network: str = "bitcoin"
    balance: float = 0.0
    total_received: float = 0.0
    total_sent: float = 0.0
    tx_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    labels: List[str] = field(default_factory=list)
    is_contract: bool = False


class BlockchainAdapter(ABC):
    """Abstract base class for blockchain adapters."""

    def __init__(self, network: str, config: Dict[str, Any] = None):
        self.network = network
        self.config = config or {}
        self._cache: Dict[str, Any] = {}
        self._rate_limiter = RateLimiter(
            max_per_second=(config or {}).get("rate_limit_per_second", 5.0)
        )
        self._request_count = 0

    @abstractmethod
    def get_transaction(self, tx_hash: str) -> Dict[str, Any]:
        """Fetch transaction details by hash."""
        pass

    @abstractmethod
    def get_address_transactions(self, address: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch transactions for an address."""
        pass

    @abstractmethod
    def get_address_info(self, address: str) -> AddressInfo:
        """Fetch address information."""
        pass

    @abstractmethod
    def get_block(self, height_or_hash: str) -> BlockInfo:
        """Fetch block information."""
        pass

    @abstractmethod
    def broadcast_transaction(self, raw_tx: str) -> str:
        """Broadcast a raw transaction."""
        pass

    def _cache_key(self, method: str, *args) -> str:
        data = f"{method}:{':'.join(str(a) for a in args)}"
        return hashlib.md5(data.encode()).hexdigest()

    def _get_cached(self, key: str) -> Optional[Any]:
        if key in self._cache:
            entry = self._cache[key]
            if time.time() - entry["time"] < self.config.get("cache_ttl", 300):
                return entry["data"]
            del self._cache[key]
        return None

    def _set_cached(self, key: str, data: Any) -> None:
        self._cache[key] = {"data": data, "time": time.time()}

    def clear_cache(self) -> None:
        self._cache.clear()

    @property
    def request_count(self) -> int:
        return self._request_count


class RateLimiter:
    """Token bucket rate limiter."""

    def __init__(self, max_per_second: float = 5.0):
        self.max_per_second = max_per_second
        self.tokens = max_per_second
        self.last_update = time.time()
        self._lock = False

    def acquire(self) -> bool:
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.max_per_second, self.tokens + elapsed * self.max_per_second)
        self.last_update = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    def wait(self) -> None:
        while not self.acquire():
            time.sleep(0.01)


class MockBlockchainAdapter(BlockchainAdapter):
    """
    Mock blockchain adapter for testing and demonstration.
    Generates realistic-looking blockchain data for analysis.
    """

    def __init__(self, network: str = "bitcoin", config: Dict[str, Any] = None):
        super().__init__(network, config)
        self._transactions: Dict[str, Dict[str, Any]] = {}
        self._addresses: Dict[str, AddressInfo] = {}
        self._seed_transactions()

    def _seed_transactions(self) -> None:
        """Generate seed transaction data for testing."""
        addresses = [f"1A{hashlib.sha256(f'addr{i}'.encode()).hexdigest()[:33]}" for i in range(20)]
        for i, addr in enumerate(addresses):
            self._addresses[addr] = AddressInfo(
                address=addr,
                network=self.network,
                balance=float(100 * (i + 1)),
                total_received=float(500 * (i + 1)),
                total_sent=float(400 * (i + 1)),
                tx_count=10 + i,
            )

    def get_transaction(self, tx_hash: str) -> Dict[str, Any]:
        """Fetch or generate transaction data."""
        cache_key = self._cache_key("tx", tx_hash)
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        self._rate_limiter.wait()
        self._request_count += 1

        if tx_hash in self._transactions:
            return self._transactions[tx_hash]

        tx_data = self._generate_mock_transaction(tx_hash)
        self._transactions[tx_hash] = tx_data
        self._set_cached(cache_key, tx_data)
        return tx_data

    def _generate_mock_transaction(self, tx_hash: str) -> Dict[str, Any]:
        """Generate realistic mock transaction data."""
        import random
        random.seed(hashlib.sha256(tx_hash.encode()).hexdigest())

        num_inputs = random.randint(1, 5)
        num_outputs = random.randint(1, 8)
        total_value = random.uniform(0.001, 100.0)

        inputs = []
        for i in range(num_inputs):
            addr_hash = hashlib.sha256(f"{tx_hash}_in_{i}".encode()).hexdigest()[:33]
            inputs.append({
                "address": f"1A{addr_hash}",
                "value": total_value / num_inputs + random.uniform(-0.01, 0.01),
                "prev_tx_hash": hashlib.sha256(f"prev_{tx_hash}_{i}".encode()).hexdigest(),
                "prev_tx_index": random.randint(0, 5),
            })

        outputs = []
        for i in range(num_outputs):
            addr_hash = hashlib.sha256(f"{tx_hash}_out_{i}".encode()).hexdigest()[:33]
            outputs.append({
                "address": f"1B{addr_hash}",
                "value": total_value / num_outputs + random.uniform(-0.01, 0.01),
                "index": i,
                "spent": random.random() > 0.3,
            })

        return {
            "tx_hash": tx_hash,
            "block_height": random.randint(700000, 850000),
            "timestamp": datetime.utcnow().isoformat(),
            "network": self.network,
            "inputs": inputs,
            "outputs": outputs,
            "fee": random.uniform(0.0001, 0.01),
            "size": random.randint(200, 2000),
            "confirmations": random.randint(1, 100),
        }

    def get_address_transactions(self, address: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch transactions for an address."""
        self._rate_limiter.wait()
        self._request_count += 1

        txs = []
        for i in range(min(limit, 10)):
            tx_hash = hashlib.sha256(f"{address}_tx_{i}".encode()).hexdigest()
            tx = self.get_transaction(tx_hash)
            txs.append(tx)
        return txs

    def get_address_info(self, address: str) -> AddressInfo:
        """Fetch address information."""
        self._rate_limiter.wait()
        self._request_count += 1

        if address in self._addresses:
            return self._addresses[address]

        return AddressInfo(
            address=address,
            network=self.network,
            balance=0.0,
            total_received=0.0,
            total_sent=0.0,
            tx_count=0,
        )

    def get_block(self, height_or_hash: str) -> BlockInfo:
        """Fetch block information."""
        self._rate_limiter.wait()
        self._request_count += 1

        try:
            height = int(height_or_hash)
        except ValueError:
            height = 800000

        return BlockInfo(
            height=height,
            hash=hashlib.sha256(f"block_{height}".encode()).hexdigest(),
            timestamp=datetime.utcnow(),
            tx_count=2500,
            size=1500000,
            previous_hash=hashlib.sha256(f"block_{height-1}".encode()).hexdigest(),
        )

    def broadcast_transaction(self, raw_tx: str) -> str:
        """Mock broadcast."""
        self._rate_limiter.wait()
        return hashlib.sha256(raw_tx.encode()).hexdigest()


class BlockchainAdapterFactory:
    """Factory for creating blockchain adapters."""

    _adapters: Dict[str, type] = {
        "mock": MockBlockchainAdapter,
    }

    @classmethod
    def register(cls, name: str, adapter_class: type) -> None:
        cls._adapters[name] = adapter_class

    @classmethod
    def create(cls, adapter_type: str = "mock", network: str = "bitcoin", **kwargs) -> BlockchainAdapter:
        if adapter_type not in cls._adapters:
            raise ValueError(f"Unknown adapter type: {adapter_type}. Available: {list(cls._adapters.keys())}")
        return cls._adapters[adapter_type](network=network, config=kwargs)

    @classmethod
    def available_adapters(cls) -> List[str]:
        return list(cls._adapters.keys())
