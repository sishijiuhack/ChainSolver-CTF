"""Blockchain utility tools for ChainSolver MCP server."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class DecodedTransaction:
    tx_hash: str | None
    from_address: str | None
    to_address: str | None
    value: int | None
    calldata: str | None
    chain_id: int | None


def decode_transaction(tx_hash: str | None = None, raw_tx: dict[str, Any] | None = None) -> dict[str, Any]:
    """Decode transaction input from hash lookup result or already-fetched raw object."""

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


def decode_event(tx_hash: str, event_signature: str, rpc_url: str) -> dict[str, Any]:
    """Decode event logs from a transaction matching the given event signature.

    Args:
        tx_hash: Transaction hash to fetch logs from.
        event_signature: Human-readable event signature, e.g. "Transfer(address,address,uint256)".
        rpc_url: Ethereum-compatible JSON-RPC endpoint.
    """
    try:
        from web3 import Web3
        from eth_abi import decode as abi_decode
    except ImportError:
        return {"error": "web3 or eth_abi not installed"}

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    receipt = w3.eth.get_transaction_receipt(tx_hash)  # type: ignore[arg-type]

    topic = Web3.keccak(text=event_signature).hex()
    matched: list[dict[str, Any]] = []

    for log in receipt["logs"]:
        if log["topics"] and log["topics"][0].hex() == topic:
            # Parse param types from signature e.g. "Transfer(address,address,uint256)"
            inner = event_signature[event_signature.index("(") + 1 : event_signature.rindex(")")]
            types = [t.strip() for t in inner.split(",") if t.strip()]
            try:
                decoded_data = abi_decode(types, bytes.fromhex(log["data"][2:] if log["data"].startswith("0x") else log["data"]))
                matched.append({
                    "log_index": log["logIndex"],
                    "address": log["address"],
                    "decoded": list(decoded_data),
                })
            except Exception as exc:
                matched.append({"log_index": log["logIndex"], "error": str(exc)})

    return {
        "tx_hash": tx_hash,
        "event_signature": event_signature,
        "topic": topic,
        "matches": matched,
    }


def call_contract(
    contract_address: str,
    abi: list[dict[str, Any]],
    function_name: str,
    params: list[Any],
    rpc_url: str,
) -> dict[str, Any]:
    """Call a read-only contract function.

    Args:
        contract_address: Target contract address.
        abi: Contract ABI as a list of dicts.
        function_name: Name of the function to call.
        params: Positional arguments for the function.
        rpc_url: Ethereum-compatible JSON-RPC endpoint.
    """
    try:
        from web3 import Web3
    except ImportError:
        return {"error": "web3 not installed"}

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    contract = w3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=abi)
    fn = contract.functions[function_name]
    result = fn(*params).call()
    return {
        "contract": contract_address,
        "function": function_name,
        "params": params,
        "result": result,
    }


def send_transaction(
    to: str,
    data: str,
    value: int,
    rpc_url: str,
    private_key: str | None = None,
    from_address: str | None = None,
    gas: int = 300_000,
) -> dict[str, Any]:
    """Sign and broadcast a transaction. Use only on CTF/test networks.

    Supports two modes:
    - private_key mode: signs locally with the given hex private key.
    - unlocked account mode: omit private_key and supply from_address instead;
      relies on the node having that account unlocked (Hardhat/Anvil/Ganache).

    Args:
        to: Recipient address.
        data: Hex-encoded calldata (with or without 0x prefix).
        value: Wei to send.
        rpc_url: Ethereum-compatible JSON-RPC endpoint.
        private_key: Sender private key (hex). Optional if from_address is set.
        from_address: Sender address for unlocked-account mode. Optional if private_key is set.
        gas: Gas limit (default 300000).
    """
    try:
        from web3 import Web3
    except ImportError:
        return {"error": "web3 not installed"}

    if not private_key and not from_address:
        return {"error": "Either private_key or from_address must be provided"}

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    calldata = data if data.startswith("0x") else "0x" + data

    if private_key:
        # --- signed mode ---
        account = w3.eth.account.from_key(private_key)
        sender = account.address
        nonce = w3.eth.get_transaction_count(sender)
        tx = {
            "to": Web3.to_checksum_address(to),
            "data": calldata,
            "value": value,
            "gas": gas,
            "gasPrice": w3.eth.gas_price,
            "nonce": nonce,
            "chainId": w3.eth.chain_id,
        }
        signed = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    else:
        # --- unlocked account mode (test node) ---
        sender = Web3.to_checksum_address(from_address)  # type: ignore[arg-type]
        tx_hash = w3.eth.send_transaction({
            "from": sender,
            "to": Web3.to_checksum_address(to),
            "data": calldata,
            "value": value,
            "gas": gas,
        })

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    return {
        "tx_hash": tx_hash.hex(),
        "from": sender,
        "to": to,
        "value": value,
        "status": "success" if receipt.get("status") == 1 else "reverted",
        "gas_used": receipt.get("gasUsed"),
    }


def get_storage_slots(
    contract_address: str,
    rpc_url: str,
    slots: list[int] | None = None,
) -> dict[str, Any]:
    """Read raw storage slots from a contract.

    Args:
        contract_address: Target contract address.
        rpc_url: Ethereum-compatible JSON-RPC endpoint.
        slots: List of slot indices to read. Defaults to slots 0-9.
    """
    try:
        from web3 import Web3
    except ImportError:
        return {"error": "web3 not installed"}

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    checksum = Web3.to_checksum_address(contract_address)
    indices = slots if slots is not None else list(range(10))

    result: dict[str, Any] = {}
    for slot in indices:
        raw = w3.eth.get_storage_at(checksum, slot)
        raw_hex = raw.hex()
        entry: dict[str, Any] = {"hex": raw_hex}

        # Detect Solidity dynamic string/bytes encoding:
        # If the lowest bit is 1 and value > 1, it's a long dynamic string stored
        # across keccak256(slot)-derived slots.
        int_val = int(raw_hex, 16)
        if int_val > 1 and (int_val & 1) == 1:
            byte_length = (int_val - 1) // 2
            entry["type"] = "dynamic_string"
            entry["byte_length"] = byte_length
            # Derive base slot: keccak256(slot as 32-byte big-endian)
            import hashlib
            slot_bytes = slot.to_bytes(32, "big")
            base_slot_hex = hashlib.new("sha3_256", slot_bytes).digest()  # placeholder
            # Use Web3.keccak for correct keccak256
            base_slot_int = int(Web3.keccak(slot_bytes).hex(), 16)
            num_chunks = (byte_length + 31) // 32
            string_bytes = b""
            for i in range(num_chunks):
                chunk = w3.eth.get_storage_at(checksum, base_slot_int + i)
                string_bytes += bytes(chunk)
            string_bytes = string_bytes[:byte_length]
            try:
                entry["decoded"] = string_bytes.decode("utf-8")
            except Exception:
                entry["decoded"] = string_bytes.hex()
        elif int_val > 0 and (int_val & 1) == 0 and int_val < 0x100:
            # Short string: length = int_val // 2, data packed in same slot
            byte_length = int_val // 2
            if byte_length > 0:
                data_bytes = raw[: byte_length]
                try:
                    entry["type"] = "short_string"
                    entry["byte_length"] = byte_length
                    entry["decoded"] = data_bytes.decode("utf-8")
                except Exception:
                    pass

        result[str(slot)] = entry

    return {
        "contract": contract_address,
        "slots": result,
    }


def encode_calldata(function_signature: str, params: list[Any] | None = None) -> dict[str, Any]:
    """ABI-encode a function call into hex calldata.

    Args:
        function_signature: e.g. "transfer(address,uint256)" or "getFlag()".
        params: Positional arguments matching the signature types.
    """
    try:
        from web3 import Web3
        from eth_abi import encode as abi_encode
    except ImportError:
        return {"error": "web3 or eth_abi not installed"}

    selector = Web3.keccak(text=function_signature)[:4].hex()

    if not params:
        return {"selector": "0x" + selector, "calldata": "0x" + selector, "function": function_signature}

    inner = function_signature[function_signature.index("(") + 1: function_signature.rindex(")")]
    types = [t.strip() for t in inner.split(",") if t.strip()]

    try:
        encoded_params = abi_encode(types, params).hex()
    except Exception as exc:
        return {"error": f"ABI encoding failed: {exc}", "selector": "0x" + selector}

    return {
        "function": function_signature,
        "selector": "0x" + selector,
        "calldata": "0x" + selector + encoded_params,
    }


def call_contract_raw(
    contract_address: str,
    function_signature: str,
    rpc_url: str,
    params: list[Any] | None = None,
    return_types: list[str] | None = None,
) -> dict[str, Any]:
    """Call a contract function using a human-readable signature instead of a full ABI.

    Args:
        contract_address: Target contract address.
        function_signature: e.g. "balanceOf(address)" or "getFlag()".
        rpc_url: Ethereum-compatible JSON-RPC endpoint.
        params: Positional arguments matching the signature types.
        return_types: ABI return types e.g. ["uint256"] or ["string"].
                      If omitted, raw hex is returned.
    """
    try:
        from web3 import Web3
        from eth_abi import decode as abi_decode
    except ImportError:
        return {"error": "web3 or eth_abi not installed"}

    encoded = encode_calldata(function_signature, params)
    if "error" in encoded:
        return encoded

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    try:
        raw = w3.eth.call({"to": Web3.to_checksum_address(contract_address), "data": encoded["calldata"]})
    except Exception as exc:
        return {"error": f"eth_call failed: {exc}"}

    if not return_types:
        return {"contract": contract_address, "function": function_signature, "result": raw.hex()}

    try:
        decoded = abi_decode(return_types, raw)
        def _jsonify(v: Any) -> Any:
            if isinstance(v, bytes):
                return v.hex()
            if isinstance(v, (list, tuple)):
                return [_jsonify(i) for i in v]
            return v
        result: Any = _jsonify(decoded[0] if len(decoded) == 1 else list(decoded))
    except Exception as exc:
        result = {"raw": raw.hex(), "decode_error": str(exc)}

    return {
        "contract": contract_address,
        "function": function_signature,
        "params": params or [],
        "result": result,
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
