"""
Cryptographic utility functions for blockchain analysis.
Address validation, hashing, and encoding operations.
"""

import hashlib
import re
import string
from typing import Optional, Tuple, Dict, Any


# Bitcoin address patterns
BTC_P2PKH_PATTERN = re.compile(r'^[1][a-km-zA-HJ-NP-Z1-9]{25,34}$')
BTC_P2SH_PATTERN = re.compile(r'^[3][a-km-zA-HJ-NP-Z1-9]{25,34}$')
BTC_BECH32_PATTERN = re.compile(r'^bc1[a-z0-9]{39,59}$')
BTC_BECH32M_PATTERN = re.compile(r'^bc1p[a-z0-9]{58}$')

# Ethereum address pattern
ETH_ADDRESS_PATTERN = re.compile(r'^0x[0-9a-fA-F]{40}$')

# Litecoin address patterns
LTC_P2PKH_PATTERN = re.compile(r'^[L][a-km-zA-HJ-NP-Z1-9]{26,33}$')
LTC_P2SH_PATTERN = re.compile(r'^[M][a-km-zA-HJ-NP-Z1-9]{26,33}$')
LTC_BECH32_PATTERN = re.compile(r'^ltc1[a-z0-9]{39,59}$')

# Transaction hash patterns
BTC_TX_HASH_PATTERN = re.compile(r'^[0-9a-fA-F]{64}$')
ETH_TX_HASH_PATTERN = re.compile(r'^0x[0-9a-fA-F]{64}$')

# Base58 alphabet
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def validate_address(address: str, network: str = "bitcoin") -> Tuple[bool, str]:
    """
    Validate a blockchain address.
    Returns (is_valid, address_type).
    """
    if not address:
        return False, "empty"

    if network == "bitcoin":
        return _validate_bitcoin_address(address)
    elif network == "ethereum":
        return _validate_ethereum_address(address)
    elif network == "litecoin":
        return _validate_litecoin_address(address)
    else:
        return _validate_generic_address(address)


def _validate_bitcoin_address(address: str) -> Tuple[bool, str]:
    """Validate a Bitcoin address."""
    if BTC_P2PKH_PATTERN.match(address):
        return True, "p2pkh"
    elif BTC_P2SH_PATTERN.match(address):
        return True, "p2sh"
    elif BTC_BECH32M_PATTERN.match(address.lower()):
        return True, "p2tr"
    elif BTC_BECH32_PATTERN.match(address.lower()):
        return True, "p2wpkh"
    return False, "invalid"


def _validate_ethereum_address(address: str) -> Tuple[bool, str]:
    """Validate an Ethereum address."""
    if ETH_ADDRESS_PATTERN.match(address):
        if address == "0x" + "0" * 40:
            return False, "zero_address"
        return True, "eth_eoa"
    return False, "invalid"


def _validate_litecoin_address(address: str) -> Tuple[bool, str]:
    """Validate a Litecoin address."""
    if LTC_P2PKH_PATTERN.match(address):
        return True, "p2pkh"
    elif LTC_P2SH_PATTERN.match(address):
        return True, "p2sh"
    elif LTC_BECH32_PATTERN.match(address.lower()):
        return True, "p2wpkh"
    return False, "invalid"


def _validate_generic_address(address: str) -> Tuple[bool, str]:
    """Generic address validation."""
    if re.match(r'^[a-zA-Z0-9]{25,64}$', address):
        return True, "unknown"
    return False, "invalid"


def validate_tx_hash(tx_hash: str, network: str = "bitcoin") -> bool:
    """Validate a transaction hash format."""
    if network == "ethereum":
        return bool(ETH_TX_HASH_PATTERN.match(tx_hash))
    return bool(BTC_TX_HASH_PATTERN.match(tx_hash))


def double_sha256(data: bytes) -> bytes:
    """Perform double SHA-256 hash (Bitcoin standard)."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def sha256(data: bytes) -> bytes:
    """Perform single SHA-256 hash."""
    return hashlib.sha256(data).digest()


def ripemd160(data: bytes) -> bytes:
    """Perform RIPEMD-160 hash."""
    h = hashlib.new('ripemd160')
    h.update(data)
    return h.digest()


def hash160(data: bytes) -> bytes:
    """Perform Bitcoin HASH160 (RIPEMD160(SHA256(data)))."""
    return ripemd160(sha256(data))


def base58_encode(data: bytes) -> str:
    """Encode bytes to Base58."""
    num = int.from_bytes(data, 'big')
    result = []
    while num > 0:
        num, remainder = divmod(num, 58)
        result.append(BASE58_ALPHABET[remainder])
    # Add leading zeros
    for byte in data:
        if byte == 0:
            result.append('1')
        else:
            break
    return ''.join(reversed(result))


def base58_decode(encoded: str) -> bytes:
    """Decode Base58 string to bytes."""
    num = 0
    for char in encoded:
        num = num * 58 + BASE58_ALPHABET.index(char)
    # Count leading zeros
    leading_zeros = len(encoded) - len(encoded.lstrip('1'))
    # Convert to bytes
    result = num.to_bytes(max(1, (num.bit_length() + 7) // 8), 'big')
    return b'\x00' * leading_zeros + result


def base58check_encode(payload: bytes) -> str:
    """Encode with Base58Check (includes checksum)."""
    checksum = double_sha256(payload)[:4]
    return base58_encode(payload + checksum)


def base58check_decode(encoded: str) -> bytes:
    """Decode Base58Check (validates checksum)."""
    data = base58_decode(encoded)
    payload, checksum = data[:-4], data[-4:]
    expected_checksum = double_sha256(payload)[:4]
    if checksum != expected_checksum:
        raise ValueError("Invalid checksum")
    return payload


def detect_address_network(address: str) -> Tuple[Optional[str], str]:
    """Auto-detect the network and type of a blockchain address."""
    # Try Bitcoin
    valid, addr_type = _validate_bitcoin_address(address)
    if valid:
        return "bitcoin", addr_type

    # Try Ethereum
    valid, addr_type = _validate_ethereum_address(address)
    if valid:
        return "ethereum", addr_type

    # Try Litecoin
    valid, addr_type = _validate_litecoin_address(address)
    if valid:
        return "litecoin", addr_type

    return None, "unknown"


def generate_address_variations(address: str) -> Dict[str, str]:
    """Generate common address variations (lowercase, uppercase, mixed)."""
    variations = {
        "original": address,
        "lowercase": address.lower(),
        "uppercase": address.upper(),
    }
    # For Bech32 addresses
    if address.lower().startswith("bc1") or address.lower().startswith("ltc1"):
        variations["canonical"] = address.lower()
    # For Ethereum addresses with EIP-55 checksum
    elif address.startswith("0x"):
        variations["checksum"] = to_checksum_address(address)
    return variations


def to_checksum_address(address: str) -> str:
    """Convert Ethereum address to EIP-55 checksum address."""
    address = address.lower().replace("0x", "")
    hash_hex = hashlib.sha3_256(address.encode()).hexdigest()
    checksummed = "0x"
    for i, char in enumerate(address):
        if char in "0123456789":
            checksummed += char
        elif int(hash_hex[i], 16) >= 8:
            checksummed += char.upper()
        else:
            checksummed += char.lower()
    return checksummed


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            import math
            entropy -= p * math.log2(p)
    return entropy


def is_mixer_like_pattern(num_inputs: int, num_outputs: int, output_values: list) -> float:
    """
    Estimate if a transaction resembles a mixer/tumbler pattern.
    Returns confidence score 0.0-1.0.
    """
    score = 0.0

    # Multiple inputs and outputs
    if num_inputs >= 3 and num_outputs >= 3:
        score += 0.3

    # Many equal-value outputs
    if len(output_values) >= 3:
        unique_values = set(round(v, 8) for v in output_values)
        if len(unique_values) <= len(output_values) * 0.3:
            score += 0.4  # Many outputs have same value

    # Round values
    round_count = sum(1 for v in output_values if v == round(v, 0))
    if len(output_values) > 0 and round_count / len(output_values) > 0.5:
        score += 0.2

    # Similar input/output counts
    if abs(num_inputs - num_outputs) <= 2:
        score += 0.1

    return min(1.0, score)
