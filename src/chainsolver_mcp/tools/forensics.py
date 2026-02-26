"""On-chain forensics tools for ChainSolver MCP server."""

from __future__ import annotations

from typing import Any


def trace_funds(address: str, rpc_url: str, depth: int = 3) -> dict[str, Any]:
    """Trace ETH fund flows from/to an address for the most recent transactions.

    Args:
        address: Ethereum address to trace.
        rpc_url: Ethereum-compatible JSON-RPC endpoint.
        depth: How many hops to follow (default 3).
    """
    try:
        from web3 import Web3
    except ImportError:
        return {"error": "web3 not installed"}

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    checksum = Web3.to_checksum_address(address)
    latest = w3.eth.block_number

    flows: list[dict[str, Any]] = []
    seen: set[str] = {checksum}
    queue = [(checksum, 0)]

    while queue:
        current, hop = queue.pop(0)
        if hop >= depth:
            continue
        # Scan last 1000 blocks for simplicity
        for block_num in range(max(0, latest - 1000), latest + 1):
            try:
                block = w3.eth.get_block(block_num, full_transactions=True)
            except Exception:
                continue
            for tx in block.get("transactions", []):
                if tx.get("from", "").lower() == current.lower() and tx.get("value", 0) > 0:
                    dest = tx.get("to") or "contract_creation"
                    flows.append({
                        "hop": hop,
                        "from": tx["from"],
                        "to": dest,
                        "value_wei": tx["value"],
                        "tx_hash": tx["hash"].hex(),
                        "block": block_num,
                    })
                    if dest not in seen and hop + 1 < depth:
                        seen.add(dest)
                        queue.append((dest, hop + 1))

    return {"address": address, "depth": depth, "flows": flows}


def analyze_transaction_flow(tx_hash: str, rpc_url: str) -> dict[str, Any]:
    """Analyze the full call stack and event sequence of a transaction.

    Args:
        tx_hash: Transaction hash to analyze.
        rpc_url: Ethereum-compatible JSON-RPC endpoint.
    """
    try:
        from web3 import Web3
    except ImportError:
        return {"error": "web3 not installed"}

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    receipt = w3.eth.get_transaction_receipt(tx_hash)  # type: ignore[arg-type]
    tx = w3.eth.get_transaction(tx_hash)  # type: ignore[arg-type]

    events = []
    for log in receipt["logs"]:
        events.append({
            "log_index": log["logIndex"],
            "address": log["address"],
            "topics": [t.hex() for t in log["topics"]],
            "data": log["data"],
        })

    # Try debug_traceTransaction for call stack (not available on all nodes)
    call_trace = None
    try:
        call_trace = w3.manager.request_blocking(
            "debug_traceTransaction",
            [tx_hash, {"tracer": "callTracer"}],
        )
    except Exception:
        call_trace = "debug_traceTransaction not supported by this RPC endpoint"

    return {
        "tx_hash": tx_hash,
        "from": tx["from"],
        "to": tx.get("to"),
        "value": tx["value"],
        "gas_used": receipt["gasUsed"],
        "status": receipt["status"],
        "events": events,
        "call_trace": call_trace,
    }


def decode_storage(
    contract_address: str,
    abi: list[dict[str, Any]],
    variable_name: str,
    rpc_url: str,
) -> dict[str, Any]:
    """Decode a named storage variable from a contract using its ABI.

    Args:
        contract_address: Target contract address.
        abi: Contract ABI as a list of dicts.
        variable_name: Name of the state variable to read.
        rpc_url: Ethereum-compatible JSON-RPC endpoint.
    """
    try:
        from web3 import Web3
    except ImportError:
        return {"error": "web3 not installed"}

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(contract_address), abi=abi
    )

    # Find a matching getter function in the ABI
    getter = None
    for item in abi:
        if (
            item.get("type") == "function"
            and item.get("name") == variable_name
            and item.get("stateMutability") in ("view", "pure")
            and not item.get("inputs")
        ):
            getter = item
            break

    if getter is None:
        return {
            "error": f"No public getter found for '{variable_name}' in ABI. "
                     "Try get_storage_slots for raw slot access."
        }

    value = contract.functions[variable_name]().call()
    return {
        "contract": contract_address,
        "variable": variable_name,
        "value": value,
    }
