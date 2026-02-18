"""Blockchain utility tools for ChainSolver MCP server."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class DecodedTransaction:
    """A normalized decoded transaction payload."""

    tx_hash: str | None
    from_address: str | None
    to_address: str | None
    value: int | None
    calldata: str | None
    chain_id: int | None


def decode_transaction(tx_hash: str | None = None, raw_tx: dict[str, Any] | None = None) -> dict[str, Any]:
    """Decode transaction input from hash lookup result or already-fetched raw object.

    This MVP implementation normalizes transaction fields and returns a stable schema
    that downstream workflows can consume.
    """

    if not tx_hash and not raw_tx:
        raise ValueError("Either tx_hash or raw_tx must be provided")

    raw = raw_tx or {}
    decoded = DecodedTransaction(
        tx_hash=tx_hash or raw.get("hash"),
        from_address=raw.get("from"),
        to_address=raw.get("to"),
        value=_safe_int(raw.get("value")),
        calldata=raw.get("input") or raw.get("data"),
        chain_id=_safe_int(raw.get("chainId")),
    )

    return {
        "tx_hash": decoded.tx_hash,
        "from": decoded.from_address,
        "to": decoded.to_address,
        "value": decoded.value,
        "calldata": decoded.calldata,
        "chain_id": decoded.chain_id,
        "status": "decoded",
        "source": "raw_tx" if raw_tx else "tx_hash_only",
    }


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        if value.startswith("0x"):
            return int(value, 16)
        return int(value)
    raise ValueError(f"Unsupported numeric value: {value!r}")
